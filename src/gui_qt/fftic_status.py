"""FFTIC-only status panel for the existing right-side game area."""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton,
    QToolButton, QVBoxLayout, QWidget,
)

from gui_qt.theme_qt import active_palette, _c


_COLORS = {
    "ready": ("FRAMEWORK_INSTALLED_BG", "FRAMEWORK_INSTALLED_FG"),
    "info": ("FRAMEWORK_DISABLED_BG", "FRAMEWORK_DISABLED_FG"),
    "warning": ("FRAMEWORK_STAGED_BG", "FRAMEWORK_STAGED_FG"),
    "error": ("FRAMEWORK_MISSING_BG", "FRAMEWORK_MISSING_FG"),
}

_ICONS = {
    "ready": "✔",
    "info": "●",
    "warning": "●",
    "error": "✘",
}


class FfticStatusPanel(QFrame):
    """Render a controller-produced view model; perform no readiness logic."""

    recheck_requested = Signal()
    cancel_requested = Signal()
    action_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("FfticStatusPanel")
        self.setAccessibleName(self.tr("FFTIC Mod Support status"))
        self._model = None
        self._operation_active = False
        self._rows: list[QWidget] = []
        self._build()
        self.hide()

    @property
    def model(self):
        return self._model

    def _build(self) -> None:
        p = active_palette()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 2)
        outer.setSpacing(1)

        head = QWidget()
        head.setObjectName("HeaderBar")
        bar = QHBoxLayout(head)
        bar.setContentsMargins(10, 5, 8, 5)
        title = QLabel(self.tr("FFTIC Mod Support"))
        title.setStyleSheet(
            f"color:{_c(p,'TEXT_MAIN')}; font-weight:600; font-size:13px;")
        bar.addWidget(title)
        bar.addStretch(1)
        self._details_button = QToolButton()
        self._details_button.setObjectName("FormButton")
        self._details_button.setCheckable(True)
        self._details_button.setText(self.tr("View details"))
        self._details_button.setCursor(Qt.PointingHandCursor)
        self._details_button.toggled.connect(self._set_details_visible)
        bar.addWidget(self._details_button)
        self._release_notes = QToolButton()
        self._release_notes.setObjectName("FormButton")
        self._release_notes.setText(self.tr("Loader release notes"))
        self._release_notes.setEnabled(False)
        self._release_notes.clicked.connect(self._open_release_notes)
        bar.addWidget(self._release_notes)
        self._recheck = QPushButton(self.tr("Recheck"))
        self._recheck.setObjectName("FormButton")
        self._recheck.setCursor(Qt.PointingHandCursor)
        self._recheck.setToolTip(self.tr(
            "Check FFTIC status and releases without changing managed game files. "
            "A new release notice may be saved in Amethyst's configuration."))
        self._recheck.clicked.connect(self._request_recheck_or_cancel)
        bar.addWidget(self._recheck)
        outer.addWidget(head)

        self._row_host = QWidget()
        self._row_layout = QVBoxLayout(self._row_host)
        self._row_layout.setContentsMargins(0, 0, 0, 0)
        self._row_layout.setSpacing(1)
        outer.addWidget(self._row_host)

        actions = QWidget()
        actions.setObjectName("FooterBar")
        action_layout = QGridLayout(actions)
        action_layout.setContentsMargins(8, 5, 8, 5)
        action_layout.setSpacing(6)
        self._action_buttons = {}
        for index, (key, label) in enumerate((
            ("setup", self.tr("Set up FFTIC support")),
            ("repair", self.tr("Repair")),
            ("synchronize", self.tr("Synchronize profile")),
            ("update", self.tr("Update FFTIC Mod Loader")),
            ("revert_loader", self.tr("Return loader to 1.7.3")),
            ("remove", self.tr("Remove managed support")),
            ("reconcile_runtime_output", self.tr("Confirm runtime output")),
        )):
            button = QPushButton(label)
            button.setObjectName("FormButton")
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(
                lambda _checked=False, value=key: self.action_requested.emit(value))
            action_layout.addWidget(button, index // 3, index % 3)
            self._action_buttons[key] = button
        self._copy = QPushButton(self.tr("Copy Steam Launch Options"))
        self._copy.setObjectName("FormButton")
        self._copy.setCursor(Qt.PointingHandCursor)
        self._copy.clicked.connect(self._copy_steam_options)
        action_layout.addWidget(self._copy, 3, 0, 1, 3)
        for column in range(3):
            action_layout.setColumnStretch(column, 1)
        outer.addWidget(actions)

        self._details = QFrame()
        self._details.setObjectName("FfticDetails")
        detail_layout = QVBoxLayout(self._details)
        detail_layout.setContentsMargins(10, 7, 10, 8)
        self._detail_text = QPlainTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setMaximumHeight(220)
        self._detail_text.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self._detail_text.setAccessibleName(self.tr("FFTIC support details"))
        self._detail_text.setStyleSheet(
            f"QPlainTextEdit {{ background:{_c(p,'BG_DEEP')};"
            f" color:{_c(p,'TEXT_DIM')}; border:1px solid {_c(p,'BORDER')};"
            " border-radius:5px; padding:6px; font-family:monospace;"
            " font-size:11px; }")
        detail_layout.addWidget(self._detail_text)
        self._details.hide()
        outer.addWidget(self._details)

    def set_loading(self, *, preserve_status: bool = False) -> None:
        settled = preserve_status and self._model is not None
        if not settled:
            self._model = None
            self._clear_rows()
        self._copy.setEnabled(False)
        self._release_notes.setEnabled(False)
        for button in self._action_buttons.values():
            button.setEnabled(False)
        if not settled:
            self._detail_text.setPlainText(self.tr("Checking current FFTIC status…"))
        self._recheck.setEnabled(False)
        self._recheck.setText(self.tr("Checking…"))

    def set_operation(self, active: bool, phase: str = "") -> None:
        """Render a cancellable managed operation without touching lifecycle state."""
        self._operation_active = active
        self._recheck.setEnabled(True)
        self._recheck.setText(self.tr("Cancel operation") if active else self.tr("Recheck"))
        available = set(self._model.available_actions) if self._model else set()
        for key, button in self._action_buttons.items():
            button.setEnabled(False if active else bool(
                self._model and self._model.mutation_available and key in available))
        if active and phase:
            self._detail_text.setPlainText(phase)

    def _request_recheck_or_cancel(self) -> None:
        if self._operation_active:
            self.cancel_requested.emit()
        else:
            self.recheck_requested.emit()

    def set_progress(self, update) -> None:
        if self._operation_active:
            self._detail_text.setPlainText(
                f"{update.phase}\n{update.completed}/{update.total}")

    def _clear_rows(self) -> None:
        while self._row_layout.count():
            item = self._row_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._rows.clear()

    def set_status(self, model) -> None:
        self._model = model
        self._operation_active = False
        self._recheck.setEnabled(True)
        self._recheck.setText(self.tr("Recheck"))
        self._clear_rows()
        p = active_palette()
        for row in model.rows:
            bg, fg = _COLORS.get(row.severity.value, _COLORS["error"])
            widget = QWidget()
            widget.setObjectName("FfticStatusRow")
            widget.setMinimumHeight(22)
            layout = QGridLayout(widget)
            layout.setContentsMargins(10, 3, 10, 3)
            layout.setHorizontalSpacing(10)
            label = QLabel(f"{_ICONS.get(row.severity.value, '✘')}  {row.label}")
            label.setStyleSheet(f"color:{_c(p,fg)}; font-weight:600;")
            state = QLabel(row.state)
            state.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            state.setStyleSheet(f"color:{_c(p,fg)}; font-weight:600;")
            widget.setStyleSheet(f"background:{_c(p,bg)};")
            tooltip = "\n".join((row.summary, *row.details))
            widget.setToolTip(tooltip)
            widget.setAccessibleName(f"{row.label}: {row.state}")
            widget.setAccessibleDescription(tooltip)
            layout.addWidget(label, 0, 0)
            layout.addWidget(state, 0, 1)
            self._row_layout.addWidget(widget)
            self._rows.append(widget)

        unavailable = model.mutation_unavailable_reason
        action_reasons = dict(model.action_unavailable_reasons)
        available = set(model.available_actions)
        recovery = next((row for row in model.rows if row.key == "recovery"), None)
        blocked = bool(recovery and recovery.state == "Recovery required")
        for key, button in self._action_buttons.items():
            enabled = model.mutation_available and not blocked and key in available
            button.setEnabled(enabled)
            reason = (self.tr("Resolve recovery-required state before another mutation.")
                      if blocked else unavailable or action_reasons.get(key, ""))
            button.setToolTip("" if enabled else reason)
            button.setAccessibleDescription(
                "Available" if enabled else reason)
        self._copy.setEnabled(bool(model.steam_copy_text))
        self._release_notes.setEnabled(bool(model.release and model.release.notes_url))
        self._copy.setText(self.tr("Copy Steam Launch Options"))
        details = list(model.details)
        details.extend((
            self.tr("Recommended Steam Launch Options (copy action):"),
            f"  {model.steam_copy_text}",
            self.tr("Steam configuration is not edited automatically."),
        ))
        if model.steam_preserved_options:
            details.append(self.tr(
                "Safe unrelated Steam options included in the recommendation:"))
            details.extend(f"  {value}" for value in model.steam_preserved_options)
        for package in model.unsupported_packages:
            details.extend((
                self.tr("Unsupported package: {0} ({1})").format(
                    package.name, package.state),
                f"  {package.path}", f"  {package.reason}"))
        for row in model.rows:
            if row.details:
                details.append(f"{row.label}:")
                details.extend(f"  {value}" for value in row.details)
        details.extend(("", model.launch_instruction))
        self._detail_text.setPlainText("\n".join(details))
        self.show()

    def clear(self) -> None:
        self._model = None
        self._clear_rows()
        self._copy.setEnabled(False)
        self._release_notes.setEnabled(False)
        self.hide()

    def _open_release_notes(self) -> None:
        if self._model is not None and self._model.release is not None:
            QDesktopServices.openUrl(QUrl(self._model.release.notes_url))

    def _set_details_visible(self, visible: bool) -> None:
        self._details.setVisible(visible)
        self._details_button.setText(
            self.tr("Hide details") if visible else self.tr("View details"))

    def _copy_steam_options(self) -> None:
        if self._model is None or not self._model.steam_copy_text:
            return
        clipboard = QGuiApplication.clipboard()
        if clipboard is None:
            self._copy.setText(self.tr("Copy failed"))
            return
        clipboard.setText(self._model.steam_copy_text)
        self._copy.setText(self.tr("Copied ✓"))

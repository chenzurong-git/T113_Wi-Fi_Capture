from __future__ import annotations

import os
import sys


def _enable_windows_dpi_awareness() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def main() -> int:
    _enable_windows_dpi_awareness()
    from t113cap.gui import T113CaptureApp

    app = T113CaptureApp()
    if os.environ.get("T113CAP_SMOKE_TEST") == "1" or "--smoke-test" in sys.argv:
        app.after(1800, app.destroy)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())

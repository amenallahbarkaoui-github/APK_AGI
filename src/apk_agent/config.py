"""Application configuration — loads from .env."""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


@dataclass
class KeystoreConfig:
    """Java keystore settings for APK signing."""

    path: Optional[str] = None
    password: str = "android"
    key_alias: str = "androiddebugkey"
    key_password: str = "android"


@dataclass
class AppConfig:
    """Central application configuration."""

    # LLM
    api_key: str = ""
    api_base_url: str = ""
    model_name: str = ""

    # Tool paths (empty → auto-detect from PATH)
    apktool_path: str = ""
    jadx_path: str = ""
    apksigner_path: str = ""
    zipalign_path: str = ""
    dex2jar_path: str = ""
    aapt2_path: str = ""

    # Workspace
    workspace_root: str = "./workspace"

    # Signing
    keystore: KeystoreConfig = field(default_factory=KeystoreConfig)

    # Limits
    max_apk_size_mb: int = 200

    # Context window in tokens — set via CONTEXT_WINDOW env var, --context-window, or /context
    context_window: int = 0

    # Telegram bot bridge
    telegram_bot_token: str = ""
    telegram_allowed_chat_ids: tuple[int, ...] = field(default_factory=tuple)
    telegram_auto_start: bool = False
    telegram_poll_timeout_sec: int = 30

    # --- resolved tool paths (filled by validate) ---
    _resolved_tools: dict[str, str] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------
    @classmethod
    def load(cls, env_file: Optional[str] = None) -> "AppConfig":
        """Load configuration from environment / .env file."""
        if env_file:
            load_dotenv(env_file)
        else:
            load_dotenv()

        allowed_chat_ids_raw = os.getenv("TELEGRAM_ALLOWED_CHAT_IDS", "")
        allowed_chat_ids: list[int] = []
        for token in allowed_chat_ids_raw.replace(",", " ").split():
            token = token.strip()
            if not token:
                continue
            try:
                allowed_chat_ids.append(int(token))
            except ValueError:
                continue

        cfg = cls(
            api_key=os.getenv("API_KEY", os.getenv("OPENROUTER_API_KEY", "")),
            api_base_url=os.getenv("API_BASE_URL", "").strip(),
            model_name=os.getenv("MODEL_NAME", "").strip(),
            apktool_path=os.getenv("APKTOOL_PATH", ""),
            jadx_path=os.getenv("JADX_PATH", ""),
            apksigner_path=os.getenv("APKSIGNER_PATH", ""),
            zipalign_path=os.getenv("ZIPALIGN_PATH", ""),
            dex2jar_path=os.getenv("DEX2JAR_PATH", ""),
            aapt2_path=os.getenv("AAPT2_PATH", ""),
            workspace_root=os.getenv("WORKSPACE_ROOT", "./workspace"),
            keystore=KeystoreConfig(
                path=os.getenv("KEYSTORE_PATH") or None,
                password=os.getenv("KEYSTORE_PASSWORD", "android"),
                key_alias=os.getenv("KEY_ALIAS", "androiddebugkey"),
                key_password=os.getenv("KEY_PASSWORD", "android"),
            ),
            max_apk_size_mb=int(os.getenv("MAX_APK_SIZE_MB", "200")),
            context_window=int(os.getenv("CONTEXT_WINDOW", "0")),
            telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
            telegram_allowed_chat_ids=tuple(allowed_chat_ids),
            telegram_auto_start=os.getenv("TELEGRAM_AUTO_START", "false").lower() in ("true", "1", "yes"),
            telegram_poll_timeout_sec=max(5, int(os.getenv("TELEGRAM_POLL_TIMEOUT_SEC", "30"))),
        )
        return cfg

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def resolve_tool(self, name: str, explicit_path: str, binary_names: list[str]) -> str:
        """Resolve a tool's absolute path.

        Priority: explicit config > project-local tools/bin/ > system PATH.
        On Windows, .bat/.exe variants are preferred over bare names to
        avoid WinError 193 when accidentally invoking a Unix shell script.
        """
        # 1. Explicit path from .env
        if explicit_path and Path(explicit_path).is_file():
            return str(Path(explicit_path).resolve())

        # On Windows, reorder so .bat/.exe/.cmd come first
        is_win = platform.system() == "Windows"
        if is_win:
            win_first = [b for b in binary_names if b.endswith((".bat", ".exe", ".cmd"))]
            rest = [b for b in binary_names if b not in win_first]
            binary_names = win_first + rest

        # 2. Project-local tools/bin/ directory
        project_bin = Path(__file__).resolve().parent.parent.parent / "tools" / "bin"
        if project_bin.is_dir():
            for bn in binary_names:
                # Direct in bin/
                candidate = project_bin / bn
                if candidate.is_file():
                    return str(candidate)
                # In subdirectory bin/ (e.g., jadx/bin/jadx.bat)
                for subdir in project_bin.iterdir():
                    if subdir.is_dir():
                        sub_candidate = subdir / "bin" / bn
                        if sub_candidate.is_file():
                            return str(sub_candidate)
                        # Direct in subdir (e.g., dex2jar/d2j-dex2jar.bat)
                        sub_candidate = subdir / bn
                        if sub_candidate.is_file():
                            return str(sub_candidate)

        # 3. System PATH
        for bn in binary_names:
            found = shutil.which(bn)
            if found:
                return found
        return ""

    def validate(self) -> list[str]:
        """Validate config; returns list of warnings (empty == all OK)."""
        warnings: list[str] = []

        if not self.api_key:
            warnings.append("API_KEY not set — LLM calls will fail.")
        if not self.api_base_url:
            warnings.append("API_BASE_URL not set — LLM provider endpoint is required.")
        if not self.model_name:
            warnings.append("MODEL_NAME not set — choose a model in .env or via --model.")

        # Tool resolution
        self._resolved_tools["apktool"] = self.resolve_tool(
            "apktool", self.apktool_path, ["apktool", "apktool.bat"]
        )
        self._resolved_tools["jadx"] = self.resolve_tool(
            "jadx", self.jadx_path, ["jadx", "jadx.bat"]
        )
        self._resolved_tools["apksigner"] = self.resolve_tool(
            "apksigner",
            self.apksigner_path,
            ["apksigner", "apksigner.bat", "uber-apk-signer", "uber-apk-signer.jar"],
        )
        self._resolved_tools["zipalign"] = self.resolve_tool(
            "zipalign", self.zipalign_path, ["zipalign", "zipalign.exe"]
        )
        self._resolved_tools["dex2jar"] = self.resolve_tool(
            "dex2jar",
            self.dex2jar_path,
            ["d2j-dex2jar", "d2j-dex2jar.bat", "d2j-dex2jar.sh"],
        )
        self._resolved_tools["aapt2"] = self.resolve_tool(
            "aapt2", self.aapt2_path, ["aapt2", "aapt2.exe"]
        )

        for tool_name, resolved in self._resolved_tools.items():
            if not resolved:
                warnings.append(
                    f"{tool_name} not found in PATH or configured path. "
                    f"Set {tool_name.upper()}_PATH in .env or install it."
                )

        if self.telegram_bot_token and not self.telegram_allowed_chat_ids:
            warnings.append(
                "TELEGRAM_BOT_TOKEN is set but TELEGRAM_ALLOWED_CHAT_IDS is empty — "
                "Telegram bot will not accept any chats."
            )
        if self.telegram_allowed_chat_ids and not self.telegram_bot_token:
            warnings.append(
                "TELEGRAM_ALLOWED_CHAT_IDS is set but TELEGRAM_BOT_TOKEN is missing — "
                "Telegram bot bridge cannot start."
            )

        # Workspace dir
        ws = Path(self.workspace_root)
        ws.mkdir(parents=True, exist_ok=True)

        return warnings

    def get_tool_path(self, name: str) -> str:
        """Return resolved tool path."""
        return self._resolved_tools.get(name, "")

    @property
    def telegram_enabled(self) -> bool:
        """Return True when the Telegram bridge is configured and authorized."""
        return bool(self.telegram_bot_token and self.telegram_allowed_chat_ids)

    @property
    def workspace_path(self) -> Path:
        ws = Path(self.workspace_root)
        if not ws.is_absolute():
            # Resolve relative paths against the .env file location so that
            # CLI and Telegram bot (possibly different CWDs) agree on the
            # same workspace.  If no .env is found, fall back to CWD.
            from dotenv import find_dotenv
            env_file = find_dotenv(usecwd=True)
            if env_file:
                return (Path(env_file).resolve().parent / ws).resolve()
        return ws.resolve()

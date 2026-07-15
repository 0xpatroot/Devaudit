import os
import json

class Config:
    def __init__(self):
        self.language = "en"
        self.translations = {}
        self.fallback_translations = {}
        self.exclude = []
        self.min_severity = "INFO"
        self.scans = {}

        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        self.trans_dir = os.path.join(os.path.dirname(self.base_dir), "translations")
        if not os.path.exists(self.trans_dir):
            self.trans_dir = os.path.join(self.base_dir, "translations")

        self.load_translations("en", is_fallback=True)
        self.load_translations("en")
        self.load_project_config()

    def load_project_config(self):
        config_path = os.path.join(os.getcwd(), ".devaudit.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.language = data.get("language", self.language)
                self.min_severity = data.get("min_severity", self.min_severity)
                self.exclude = data.get("exclude", self.exclude)
                self.scans = data.get("scans", self.scans)
                self.load_translations(self.language)
            except Exception:
                pass

    def load_translations(self, lang_code, is_fallback=False):
        lang_file = os.path.join(self.trans_dir, f"{lang_code}.json")
        if not os.path.exists(lang_file):

            parent_dir = os.path.dirname(os.path.abspath(__file__))
            lang_file = os.path.join(parent_dir, "..", "translations", f"{lang_code}.json")
            if not os.path.exists(lang_file):
                return

        try:
            with open(lang_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if is_fallback:
                    self.fallback_translations = data
                else:
                    self.translations = data
        except Exception:
            pass

    def set_language(self, lang_code):
        self.language = lang_code
        self.load_translations(lang_code)

    def t(self, key, **kwargs):

        message = self.translations.get(key)
        if message is None:
            message = self.fallback_translations.get(key, key)

        try:
            return message.format(**kwargs)
        except Exception:
            return message

config = Config()

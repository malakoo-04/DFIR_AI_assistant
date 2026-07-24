from pathlib import Path

from dfir_ntfs import MFT

from modules.parsers.base_parser import BaseParser


class MFTParser(BaseParser):
    """
    Parser du Master File Table ($MFT).
    """

    def parse(self, artifact_path: Path) -> list[dict]:

        results = []
        

        with artifact_path.open("rb") as f:

            mft = MFT.MasterFileTableParser(f)

            for record in mft.file_records():
                filenames = []
                try:

                    flags = record.get_flags()

                    mft_reference = record.get_master_file_table_number()
                    sequence_number = record.get_sequence_number()

                    # Référence combinée (48 bits record + 16 bits sequence),
                    # directement comparable au FRN retourné par USNParser.
                    file_reference = self._build_file_reference(
                        mft_reference,
                        sequence_number,
                    )

                    # Reconstruction du/des chemin(s) complet(s)
                    try:
                        full_paths = [
                            str(path).replace("/", "\\")
                            for path in (mft.build_full_paths(record) or [])
                            if path
                        ]
                    except Exception:
                        full_paths = []

                    # Hardlinks -> plusieurs chemins possibles pour un même
                    # enregistrement. On expose un chemin principal et les
                    # chemins alternatifs séparément, plutôt que de forcer
                    # chaque consommateur à interpréter une liste.
                    primary_path = full_paths[0] if full_paths else None
                    alternate_paths = full_paths[1:] if len(full_paths) > 1 else []

                    entry = {

                        "artifact_type": "mft",

                        "source_path": str(artifact_path),

                        "mft_reference": mft_reference,

                        "sequence_number": sequence_number,

                        "file_reference": file_reference,

                        "in_use": record.is_in_use(),

                        "flags": flags,

                        "is_directory": bool(flags & 0x02),

                        "is_file": not bool(flags & 0x02),

                        "filename": None,

                        "primary_path": primary_path,

                        "alternate_paths": alternate_paths,

                        "parent_reference": None,

                        "allocated_size": None,

                        "real_size": None,

                        "si_created": None,
                        "si_modified": None,
                        "si_accessed": None,
                        "si_entry_modified": None,

                        "fn_created": None,
                        "fn_modified": None,
                        "fn_accessed": None,
                        "fn_entry_modified": None,

                        "usn": None,

                        "file_attributes": None,
                    }

                    for attr in record.attributes():

                        try:

                            # -----------------------------
                            # $STANDARD_INFORMATION
                            # -----------------------------
                            if attr.type_code == 16:

                                si = attr.value_decoded()

                                entry["si_created"] = si.get_ctime()
                                entry["si_modified"] = si.get_mtime()
                                entry["si_accessed"] = si.get_atime()
                                entry["si_entry_modified"] = si.get_etime()

                                entry["usn"] = si.get_usn()

                                entry["file_attributes"] = si.get_file_attributes()

                            # -----------------------------
                            # $FILE_NAME
                            # -----------------------------
                            elif attr.type_code == 48:
                                fn = attr.value_decoded()
                                
                                filename = fn.get_file_name()

                                if filename not in filenames:
                                    filenames.append(filename)

                               

                                entry["filename"] = filenames[0] if filenames else None
                                entry["alternate_filenames"] = filenames[1:]

                                entry["parent_reference"] = fn.get_parent_directory()

                                entry["allocated_size"] = fn.get_allocated_length()

                                entry["real_size"] = fn.get_file_size()

                                entry["fn_created"] = fn.get_ctime()

                                entry["fn_modified"] = fn.get_mtime()

                                entry["fn_accessed"] = fn.get_atime()

                                entry["fn_entry_modified"] = fn.get_etime()

                        except Exception as exc:
                            print(
                                f"[MFT] Attribute parsing error "
                                f"(record {mft_reference}): {exc}"
                            )

                    results.append(entry)
                except Exception as exc:
                    print(f"[MFT] Failed record: {exc}")

        return results

    @staticmethod
    def _build_file_reference(record_number: int, sequence_number: int) -> int:
        """
        Construit une référence de fichier NTFS 64 bits
        (48 bits record number + 16 bits sequence number),
        directement comparable au FRN produit par USNParser.
        """

        try:
            return MFT.EncodeFileRecordSegmentReference(
                record_number,
                sequence_number,
            )
        except AttributeError:
            # Fallback si l'API du module ne l'expose pas :
            # même disposition binaire, calculée manuellement.
            return ((sequence_number & 0xFFFF) << 48) | (
                record_number & 0xFFFFFFFFFFFF
            )
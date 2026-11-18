import hashlib
import csv
import os
import argparse
from pathlib import Path
from datetime import datetime
import re
BASE_DIR = Path(__file__). resolve().parent
OUTPUT_DIR = BASE_DIR / "output"


def load_reference_hashes(filename):
    """Load known SHA-256 hashes from the reference CSV."""

    reference_hashes = {}

    try:
        with open(filename, "r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)

            if reader.fieldnames is None:
                raise ValueError("The refernce CSV is empty.")
            if "sha256" not in reader.fieldnames or "label" not in reader.fieldnames:
                raise ValueError("The CSV must contain sha256 and label columns.")
            for row in reader:
                file_hash = row.get("sha256", "").strip().lower()
                label = row.get("label", "").strip()

                if not file_hash or not label:
                    raise ValueError("A reference row has missing infotrmation.")
                if not re.fullmatch(r"[0-9a-f]{64}", file_hash):
                    raise ValueError("A reference row contains an invalid SHA-256 hash.")
                if file_hash in reference_hashes:
                    raise ValueError("A reference hash appears more than once.")
                reference_hashes[file_hash] = label

    except FileNotFoundError:
        raise FileNotFoundError("The reference CSV could not be found.")
    except (OSError, UnicodeError, csv.Error) as error:
        raise ValueError(f"Could not read the reference CSV: {error}")
    return reference_hashes


def calculate_sha256(filename):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()

    try:
        with open (filename, "rb") as file:
            while True:
                data = file.read(4096)
                if not data:
                    break
                sha256_hash.update(data)
        return sha256_hash.hexdigest()
    except OSError as error:
        raise OSError(f"Could not read {filename}: {error}")


def scan_folder(folder_path):
    """Find and collect information about every file in a folder."""
    file_records = []
    scan_errors = []
    folder = Path(folder_path)

    if not folder.exists():
        raise FileNotFoundError("The selected folder does not exist.")
    if not folder.is_dir():
        raise NotADirectoryError("The selected path is not a folder.")
    for filename in folder.iterdir():
        if not filename.is_file():
            continue
        if filename.name.lower() == "hashes_reference.csv":
            continue

        try:
            file_info = filename.stat()
            file_hash = calculate_sha256(filename)
            file_details = {
                "filename": filename.name,
                "extension": filename.suffix,
                "size": file_info.st_size,
                "last_modified": datetime.fromtimestamp(
                    file_info.st_mtime
                ).astimezone().isoformat(timespec="seconds"),
                "sha256": file_hash
            }

            file_records.append(file_details)
        except OSError as error:
            scan_errors.append(f"{filename.name}: {error}")
            print(f"Could not process {filename.name}: {error}")
    return file_records, scan_errors


def analyse_files(file_records, reference_hashes):
    """Compare file hashes against the refernce list."""
    for file_details in file_records:
        file_hash = file_details["sha256"]
        if file_hash in reference_hashes:
            file_details["status"] = "KNOWN"
            file_details["reference_label"] = reference_hashes[file_hash]
        else:
            file_details["status"] = "UNKNOWN"
            file_details["reference_label"] = "No reference match"
    return file_records


def find_duplicates(file_records):
    """Find files that have identical SHA-256 hashes."""
    hash_groups = {}
    for file_details in file_records:
        file_hash = file_details["sha256"]
        if file_hash not in hash_groups:
            hash_groups[file_hash] = []
        hash_groups[file_hash].append(file_details["filename"])
    duplicates = {}

    for file_hash, filenames in hash_groups.items():
        if len(filenames) > 1:
            duplicates[file_hash] = filenames
    for file_details in file_records:
        matching_files = duplicates.get(
            file_details["sha256"], []
        )

        file_details["duplicates"] = ", ".join(matching_files)
        if matching_files:
            file_details["duplicate_status"] = "DUPLICATE"
        else:
            file_details["duplicate_status"] = "UNIQUE"
    return duplicates


def save_reports(file_records, duplicates, scan_errors, output_folder):
    """Save the investigation results to CSV and TXT files."""
    output_path = Path(output_folder)
    output_path.mkdir(parents=True, exist_ok=True)

    csv_file = output_path / "triage_report.csv"
    txt_file = output_path / "triage_summary.txt"

    fieldnames = [
        "filename",
        "extension",
        "size",
        "last_modified",
        "sha256",
        "status",
        "reference_label",
        "duplicate_status",
        "duplicates"
    ]
    try:
        with open(csv_file, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for file_details in file_records:
                writer.writerow(file_details)

        total_files = len(file_records)
        known_files = sum(
            1 for item in file_records if item["status"] == "KNOWN"
        )
        unknown_files = sum(
            1 for item in file_records if item["status"] == "UNKNOWN"
        )
        duplicate_files = sum(
            len(filenames) for filenames in duplicates.values()
        )

        with open(txt_file, "w", encoding="utf-8") as file:
            file.write("FILE TRIAGE &HASH ANALYSIS REPORT\n")
            file.write("=" * 40 + "\n\n")
            file.write(f"Total files processed: {total_files}\n")
            file.write(f"Known refernce matches: {known_files}\n")
            file.write(f"Unknown files: {unknown_files}\n")
            file.write(f"Files involved in duplicates: {duplicate_files}\n\n")
            file.write("INDIVIDUAL FILE RESULTS\n")
            file.write("-" * 40 + "\n")

            for item in file_records:
                file.write(f"\nFilename: {item['filename']}\n")
                file.write(f"Extension: {item['extension']}\n")
                file.write(f"Size: {item['size']} bytes\n")
                file.write(f"Last modified: {item['last_modified']}\n")
                file.write(f"SHA-256: {item['sha256']}\n")
                file.write(f"Reference status: {item['status']}\n")
                file.write(f"Reference label: {item['reference_label']}\n")
                file.write(f"Duplicate status: {item['duplicate_status']}\n")

                if item["duplicates"]:
                    file.write(f"Matching files: {item['duplicates']}\n")
            file.write("\nDUPLICATE FILE GROUPS\n")
            file.write("-" * 40 + "\n")
            if duplicates:
                for filenames in duplicates.values():
                    file.write(", ".join(filenames) + "\n")
            else:
                file.write("No duplicate files found.\n")

            file.write("\nSCAN ERRORS\n")
            file.write("-" * 40 + "\n")
            if scan_errors:
                for error in scan_errors:
                    file.write(error + "\n")
            else:
                file.write("No scan errors.\n")

            file.write("\nIMPORTANT NOTE\n")
            file.write(
                "An unknown hash does not prove that a file is malicious. "
                "A reference match does not establish that a file is safe "
                "in every context.\n"
            )
    except OSError as error:
        raise OSError(f"Could not save the reports: {error}")
    print("\nReports successfully saved!")
    print(f"CSV report: {csv_file}")
    print(f"Text report: {txt_file}")


def main():
    """Run the complete file triage investigation."""
    parser = argparse.ArgumentParser(
        description="File Triage and SHA-256 Hash Analysis"
    )
    parser.add_argument(
        "folder",
        nargs="?",
        default="samples",
        help="Folder containing the files to analyse"
    )
    parser.add_argument(
        "--reference",
        default=str(BASE_DIR / "samples" / "hashes_reference.csv"),
        help="Path to the reference CSV file"
    )

    args = parser.parse_args()
    print("=" * 50)
    print("FILE TRIAGE & HASH ANALYSIS")
    print("=" * 50)

    try:
        print("\nLoading refernce hashes...")
        reference_hashes = load_reference_hashes(args.reference)
        print(f"Loaded {len(reference_hashes)} reference hashes.")

        print("\nScanning files...")
        file_records, scan_errors = scan_folder(args.folder)
        if not file_records:
            print("No files were successfully processed.")
            return
        print(f"Successfully processed {len(file_records)} files.")

        print("\nComparing file hashes...")
        file_records = analyse_files(
            file_records,
            reference_hashes
        )

        print("\nChecking for duplicate files...")
        duplicates = find_duplicates(file_records)

        print("\nINDIVIDUAL FILE RESULTS")
        print("-" * 50)
        for item in file_records:
            print(f"\nFilename: {item['filename']}")
            print(f"SHA-256: {item['sha256']}")
            print(f"Reference status: {item['status']}")
            print(f"Duplicate status: {item['duplicate_status']}")

        known = sum(
            1 for item in file_records if item["status"] == "KNOWN"
        )
        unknown = sum(
            1 for item in file_records if item["status"] == "UNKNOWN"
        )
        print("\nINVESTIGATION SUMMARY")
        print("-" * 50)
        print(f"Total files: {len(file_records)}")
        print(f"Known files: {known}")
        print(f"Unknown files: {unknown}")

        if duplicates:
            print("\nDuplicate groups:")
            for filenames in duplicates.values():
                print(", ".join(filenames))
        else:
            print("\nNo duplicate files found.")
        if scan_errors:
            print(f"\nFiles with errors: {len(scan_errors)}")

        print("\nSaving reports...")
        save_reports(
            file_records,
            duplicates,
            scan_errors,
            OUTPUT_DIR
        )
        print("\nInvestigation completed successfully!")
    except (FileNotFoundError, NotADirectoryError, ValueError, OSError) as error:
        print(f"\nERROR: {error}")

if __name__ == "__main__":
    main()
# File Triage & Hash Analysis

## Project Overview

This project is a Python-based File Triage and Hash Analysis tool.

The purpose of my program is to examine files, calculate their SHA-256 hashes, compare them against a reference hash list and identify duplicate files.

The tool helps demonstrate how file hashing can support cybersecurity investigations.

## Features
- Automatically scans files in a selected folder.
- Records each file's name, extension, size and last-modified time.
- Calculates a SHA-256 hash for every processed file.
- Compares hashes against the supplied reference CSV file.
- Classifies files as KNOWN or UNKNOWN.
- Identifies files with identical hashes.
- Handles common file and reference-data errors.
- Generates CSV and TXT investigation reports.

## Project Structure
- file_triage.py - Main python program.
- samples/ - Contains the supplied sample filed and refernce hashes
- output/ - Stores the generated investigation reports.
- README.md - Project explanation
- requirements.txt - Python package requirements

## Requirements
- Python 3.
- Python's built-in libraries.

## How to Run
1. Download the project folder.
2. Open the folder in Visual Studio Code.
3. Open a terminal in the folder.
4. Run thisd command: python file_triage.py
    The program will automatically analyse the files in the sample folder.

## Output
The program shows the investigation results in the terminal and saves two reports inside the output folder:
- triage_report.csv
- triage_summary.txt

## Understanding the Results
A KNOWN result means that a file's SHA-256 hash matches an entry in the supplied reference list.
An UNKNOWN result means that no matching hash was found in the reference list.
A hash match identifies identical file content but doesn't automatically prove that a file is safe or malicious.

## Project Purpose
This project demonstrates the use of Python scripting techniques in a cybersecurity context, including file handling, hashing, data structures, functions, error handling and report generation.
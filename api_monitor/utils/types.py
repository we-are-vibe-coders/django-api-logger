from enum import Enum

class CheckingConditions(Enum):
    SQL_INJECTION_SUSPECTED_CONDITIONS = [
        r"(?i)\bunion\b\s+\bselect\b",  # UNION SELECT
        r"(?i)\bdrop\b\s+\btable\b",  # DROP TABLE
        r"(?i)\bselect\b.*\bfrom\b",  # SELECT ... FROM
        r"(?i)\binsert\b\s+\binto\b",  # INSERT INTO
        r"(?i)\bupdate\b\s+\b\w+\b\s+\bset\b",  # UPDATE ... SET
        r"(?i)\bdelete\b\s+\bfrom\b",  # DELETE FROM
        r"(?i)\bcreate\b\s+\btable\b",  # CREATE TABLE
        r"(?i)\balter\b\s+\btable\b",  # ALTER TABLE
        r"(?i)\bdrop\b\s+\bdatabase\b",  # DROP DATABASE
        r"(?i)\bshutdown\b",  # SHUTDOWN command
        r"(?i)\bexec\b(\s+|\()",  # EXEC or EXEC()
        r"(?i)\bdeclare\b",  # DECLARE variable
        r"(?i)\bcast\b\(",  # CAST(...)
        r"(?i)\bconvert\b\(",  # CONVERT(...)
        r"(?i)\bbenchmark\b\s*\(",  # MySQL BENCHMARK function
        r"(?i)\bsleep\b\s*\(",  # Time-based SQLi
        r"(?i)or\s+1\s*=\s*1",  # OR 1=1
        r"(?i)and\s+1\s*=\s*1",  # AND 1=1
        r"--",  # SQL comment
        r";",  # Statement separator
        r"'",  # Single quote
        r'"',  # Double quote
        r"\*/",  # End of multi-line comment
        r"/\*",  # Start of multi-line comment
        r"%27",  # URL-encoded single quote
        r"%22",  # URL-encoded double quote
        r"%3B",  # URL-encoded semicolon
        r"%2D%2D",  # URL-encoded --
    ]
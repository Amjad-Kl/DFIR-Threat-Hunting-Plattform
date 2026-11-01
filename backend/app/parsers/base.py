"""Abstract base parser - all artifact parsers inherit from this."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Generator

from app.models.event import NormalizedEvent


class BaseParser(ABC):
    """Base class for all artifact parsers.

    Design principles:
    - Streaming: yield events one-by-one, don't load everything into memory
    - Resilient: skip corrupt records, don't crash on partial data
    - Normalized: output NormalizedEvent instances only
    """

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file.

        Args:
            file_path: Path to the artifact file

        Returns:
            True if this parser supports the file format
        """
        ...

    @abstractmethod
    def parse(
        self, file_path: Path, case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Parse the artifact and yield normalized events.

        This is a generator to support streaming processing of large files.
        Each parser MUST handle corrupt/partial records gracefully by
        logging the error and continuing to the next record.

        Args:
            file_path: Path to the artifact file
            case_id: The case this artifact belongs to
            artifact_id: The artifact record ID

        Yields:
            NormalizedEvent instances
        """
        ...

    @abstractmethod
    def get_source_type(self) -> str:
        """Return the source type identifier for events from this parser."""
        ...

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """File extensions this parser supports (e.g., ['.evtx'])."""
        ...

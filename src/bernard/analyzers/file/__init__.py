from .generic import GenericFileAnalyzer
from .pe import PEAnalyzer
from .pdf import PDFAnalyzer
from .office import OfficeAnalyzer

ALL_FILE_ANALYZERS = [
    PEAnalyzer(),
    PDFAnalyzer(),
    OfficeAnalyzer(),
    GenericFileAnalyzer(),   # always runs last as a fallback
]

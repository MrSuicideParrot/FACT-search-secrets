import sys
from pathlib import Path

from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.tag import TagColor

try:
    from ..internal.rulebook import evaluate, vulnerabilities
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from rulebook import evaluate, vulnerabilities



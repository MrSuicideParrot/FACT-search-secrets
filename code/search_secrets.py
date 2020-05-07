from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.tag import TagColor

class AnalysisPlugin(YaraBasePlugin):
    NAME = 'search_secrets'
    DESCRIPTION = 'Yara based search for common API tokens'
    VERSION = '0.1'
    FILE = __file__

    def __init__(self, plugin_administrator, config=None, recursive=True):
        super().__init__(plugin_administrator, config=config,
                         recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        file_object = super().process_object(file_object)
        self._add_tag(file_object)
        return file_object

    def _add_tag(self, file_object):
        if len(file_object.processed_analysis[self.NAME]['summary']) > 0:
            self.add_analysis_tag(
                file_object=file_object,
                tag_name='secret_token',
                value='Secret Token Found',
                color=TagColor.LIGHT_BLUE,
                propagate=True
            )

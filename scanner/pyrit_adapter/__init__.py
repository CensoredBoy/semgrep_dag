"""
PyRIT adapter layer.

- target_factory: creates OpenAIChatTarget / ToolEnabledTarget with SSL disabled
- scorer_factory: creates SubStringScorer / SelfAskTrueFalseScorer from config
- tool_target: ToolEnabledTarget -- injects tools into every API request
"""

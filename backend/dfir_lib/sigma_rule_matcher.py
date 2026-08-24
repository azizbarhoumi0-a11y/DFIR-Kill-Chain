# sigma_rule_matcher.py

class RuleMatcher:
    """Evaluates pySigma detection rules against normalized telemetry events."""

    def __init__(self, rule):
        self.rule = rule

    def match(self, event):
        """Matches event dictionary fields against Sigma rule detection definitions."""
        if not hasattr(self.rule, 'detection') or not self.rule.detection:
            return False

        detection = self.rule.detection
        detections_dict = getattr(detection, 'detections', {})

        for key, det_item in detections_dict.items():
            if key == 'condition':
                continue

            items = getattr(det_item, 'detection_items', [])
            for item in items:
                field = getattr(item, 'field', None)
                values = getattr(item, 'value', [])

                if not isinstance(values, list):
                    values = [values]

                # Field match verification
                if field and field in event and event[field]:
                    event_val = str(event[field]).lower()
                    for val in values:
                        val_str = str(val).lower()
                        if val_str and val_str in event_val:
                            return True
        return False

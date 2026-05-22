"""A poorly structured module for testing quality metrics."""

import os


class badlyNamedClass:
    def camelCaseMethod(self, data, config, extra):
        result = None
        if data:
            for item in data:
                if item.get("active"):
                    for sub in item.get("children", []):
                        if sub.get("value") > 0:
                            try:
                                result = sub["value"] * config
                            except:
                                pass
        return result

    def another_long_method(self, items, threshold, mode, flag, extra_param):
        output = []
        for i, item in enumerate(items):
            if mode == "strict":
                if item > threshold:
                    if flag:
                        for j in range(item):
                            if j % 2 == 0:
                                try:
                                    output.append(j * item)
                                except Exception:
                                    pass
            elif mode == "loose":
                if item > 0:
                    output.append(item)
        return output


def processData(raw_input):
    if raw_input:
        for item in raw_input:
            if item:
                for sub in item:
                    if sub > 0:
                        try:
                            return sub
                        except:
                            pass
    return None

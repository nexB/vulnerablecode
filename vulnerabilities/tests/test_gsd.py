from unittest import TestCase

from vulnerabilities.importers.gsd import get_references


class TestGSDImporter(TestCase):
    def test_get_references(self):
        assert get_references({"references": {
          "reference_data": [
            {
              "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
              "refsource": "CONFIRM",
              "tags": ["Vendor Advisory"],
              "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"
            }]
        }}) == ["https://kc.mcafee.com/corporate/index?page=content&id=SB10198"]
        assert get_references({"references": {
          "reference_data": [
            {
              "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
              "refsource": "CONFIRM",
              "tags": ["Vendor Advisory"],
              "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"
            }]
        }}) == ["https://kc.mcafee.com/corporate/index?page=content&id=SB10198"]

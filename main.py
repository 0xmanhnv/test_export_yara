from stix2 import parse
import json
import yara
from yara_tools import yara_tools

data = dict()


def get_pattern_stix(obj_stix):
	return obj_stix.get('pattern', None)

def get_indicator_stix(data_stix):
	data_indicator = list()

	for obj in data_stix.get('objects'):
		if obj.get('type') == 'indicator':
			data_indicator.append(obj)
	return data_indicator

def pattern_to_yara(pattern):
	if pattern.find("file:hashes") != -1:
		pattern = pattern.strip("[").strip("]")
		arr_pattern = pattern.split(" ")

		pattern_type = arr_pattern[0]
		pattern_hash = arr_pattern[2].strip("'")

		# rule = """
		# 	import "hash"
		# 	rule TEST_DARKCTI {
		# 		meta:
		# 			author: "DarkCTI"
		# 		condition:
		# 			hash.md5(0, filesize) == "bec30379078d5c5c7845d3be33707b89"

		# 	}
		# """

		# rules = yara.compile(source=rule)

		# print(dir(rules))
		rule=yara_tools.create_rule(name="TEST_DARKCTI")
		rule.add_import(name="hash")
		rule.add_meta(key="author",value="DarkCTI")
		rule.add_condition(condition="hash.md5(0, filesize) == 'bec30379078d5c5c7845d3be33707b89'")
		# rule.set_default_boolean(value="and")
		# rule.add_strings(strings="This program cannot",modifiers=['wide','ascii','nocase'])
		my_rule=rule.build_rule()
		print(type(my_rule))
		# print(pattern.strip("[").strip("]").split(" ")[2].strip("'"))
	return pattern

with open('stix_data.json') as json_file:
	data = json.load(json_file)

# print(get_indicator_stix(data))



if __name__ == '__main__':
	data_indicator = get_indicator_stix(data)

	for obj in data_indicator:
		pattern = get_pattern_stix(obj)
		print(pattern_to_yara(pattern))
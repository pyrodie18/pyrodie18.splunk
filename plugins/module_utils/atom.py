from __future__ import absolute_import, division, print_function
__metaclass__ = type
import ansible_collections.pyrodie18.splunk.plugins.module_utils.helpers as SplunkHelpers
import re
from copy import deepcopy
import json

STRIP_COMMENT = re.compile(r'\s*(<!--.*?-->|<\?.*?\?>)')
BREAK_ATTRS = re.compile(r'(?P<attrib>\w+)=\"(?P<value>[^\"]+)\"')
OPEN_TAG = re.compile(r'<(?P<tag>[\w:]+)(?P<attrs>(?:\s+[\w:-]+="[^"]*")*)>$')
CLOSED_TAG = re.compile(
    r'<(?P<tag>[\w:]+)(?P<attrs>(?:\s+[\w:-]+="[^"]*")*)\/>')
TAG = re.compile(
    r'<(?P<tag>[\w:]+)(?P<attrs>(?:\s+[\w:-]+="[^"]*")*)>(?P<value>.*?)<\/(?P=tag)>')


class XMLTag():
    """
    A XML Tag Response
    """

    def __init__(self, regex, xml):
        """
        Initialize a XML Tag object.

        Args:
            regex (re.compile): A compiled regular expression
            xml (str): XML formatted string
        """

        match = regex.match(xml.strip())
        if match is None:
            self._valid = False
            self._tag = None
            self._attrs = None
            self._value = None
        else:
            self._set_tag(match)
            self._set_attrs(match)
            self._set_value(match)
            self._valid = True

    @property
    def valid(self):
        return self._valid

    @property
    def tag(self):
        return self._tag

    @property
    def attrs(self):
        return self._attrs

    @property
    def value(self):
        return self._value

    def _set_tag(self, match):
        if "tag" in match.groupdict().keys():
            self._tag = match.group("tag")
        else:
            self._tag = None

    def _set_value(self, match):
        if "value" in match.groupdict().keys():
            self._value = match.group("value")
        else:
            self._value = None

    def _set_attrs(self, match):
        if "attrs" in match.groupdict().keys() and len(match.group("attrs")) > 0:
            attrs = match.group("attrs")
            matches = BREAK_ATTRS.findall(attrs.strip())
            if matches:
                response = {}
                for attrs_match in matches:
                    response[attrs_match[0]] = attrs_match[1]
                self._attrs = response
        else:
            self._attrs = None

    def __repr__(self):
        return f'Valid: {self._valid}  Tag:  {self._tag}  Attrs:  {self._attrs}  Value:  {self._value}'


class AtomToDict():
    """
    Parse a Splunk XML Atom output to dictionary.
    """

    def __init__(self, xml):
        """
        Initialize the class.

        Args:
            xml (str): An XML formatted string
        """
        self._original_xml = deepcopy(xml)
        xml = self._strip_comments(xml)
        self._xml = xml.strip().split('\n')
        self._dict = self._parse_xml()

    @property
    def xml(self):
        return self._original_xml

    # @property
    def parsed(self, key=None):
        if key:
            return SplunkHelpers.splunk_extract_value(self._dict, key)
        else:
            return self._dict

    def _strip_comments(self, xml):
        """
        Remove all comments and other non-parsable items from XML.

        Args:
            xml (str): XML to sanitize

        Returns:
            str: Sanitized XML
        """
        xml = STRIP_COMMENT.sub('', xml)
        return xml

    def _extract_open_tag(self, line):
        """
        Parse an open (<tag>) XML tag

        Args:
            line (str): A string of a potentially open XML tag.

        Returns:
            dict: A fully populated tag object
        """
        response = XMLTag(OPEN_TAG, line)

        return response if response.valid else None

    def _extract_tag(self, line):
        """
        Parse a (<tag>value</tag>) XML tag

        Args:
            line (str): A string of a potentially open XML tag.

        Returns:
            dict: A fully populated tag object
        """
        response = XMLTag(TAG, line)

        return response if response.valid else None

    def _extract_closed_tag(self, line):
        """
        Parse an closed (<tag/>) XML tag

        Args:
            line (str): A string of a potentially open XML tag.

        Returns:
            dict: A fully populated tag object
        """
        response = XMLTag(CLOSED_TAG, line)

        return response if response.valid else None

    def _build_dict(self):
        """
        Build a dictionary out of XML

        Returns:
            str: String formatted remainder of unparsed XML
            dict: Dictionary of parsed elements
        """
        response = {}

        while len(self._xml) > 0:
            line = self._xml.pop(0).strip()
            # Check for the end of a dict or list
            if line == "</s:dict>":
                break
            elif line == "</s:key>":
                continue
            # See if we have a complete tag
            elif (match := self._extract_tag(line)):
                if "name" in match.attrs.keys():
                    response[match.attrs['name']] = match.value
            # See if we have an open tag
            elif (match := self._extract_open_tag(line)):
                if "name" in match.attrs.keys():
                    current_key = match.attrs['name']
                    next_line = self._xml.pop(0).strip()

                    # Look at the next line and figure out what to do with the open tag
                    if next_line == "<s:list/>":
                        response[current_key] = []
                    elif next_line == "<s:dict/>":
                        response[current_key] = {}
                    else:
                        # Continue parsing the list or dictionary
                        return_value = self._build_list() if next_line == "<s:list>" else self._build_dict()
                        response[current_key] = return_value

        return response

    def _build_list(self):
        """
        Build a list out of XML

        Returns:
            str: String formatted remainder of unparsed XML
            list: List of parsed elements
        """
        response = []

        while len(self._xml) > 0:
            line = self._xml.pop(0).strip()
            # Closing the list
            if line == "</s:list>":
                break
            # Nesting List within a List
            elif line == "<s:list>":
                fragment = self._build_list()
                response.append(fragment)
            # Adding a dict
            elif line == "<s:dict>":
                fragment = self._build_list()
                response.append(fragment)
            # Empty List
            elif line == "<s:list/>":
                break
            else:
                # match = self._extract_tag(line)
                response.append(self._extract_tag(line).value)
        return response

    def _update_value(self, current_response, key, update):
        """
        Add/Update a value.  Will merge if required

        Args:
            current_response (dict): The current response
            key (str): The name of the key involved
            update (list or dict): The list or dict to add to the current_response

        Returns:
            list or dict: The updated response
        """
        if key in current_response.keys():
            orig = current_response[key]
            if isinstance(update, dict):
                orig.update(update)
                return orig
            else:
                return orig + update
        else:
            return update

    def _parse_xml(self):
        """
        Perform overall parsing of list

        Returns:
            dict: A fully parsed XML document
        """

        response = {}

        while len(self._xml) > 0:
            line = self._xml.pop(0).strip()
            if line.startswith('</'):
                try:
                    current_key
                except NameError:
                    current_key = None
                if current_key == "entry":
                    if len(self._xml) > 0:
                        continue
                return response
            elif line == "<s:list>":
                fragment = self._build_list()
                response[current_key] = fragment
            elif line == "<s:dict>":
                fragment = self._build_dict()
                return fragment
            elif (match := self._extract_tag(line)):
                response[match.tag] = match.value
            elif (match := self._extract_closed_tag(line)):
                attrs = match.attrs if match.attrs else {}
                response[match.tag] = self._update_value(
                    response, match.tag, attrs)
            else:
                match = self._extract_open_tag(line)
                current_key = match.tag
                fragment = self._parse_xml()
                if current_key == "entry":
                    if "entry" not in response.keys():
                        response["entry"] = []
                    response["entry"].append(fragment)
                else:
                    response[current_key] = fragment
        return response

    def __repr__(self):
        return json.dumps(self._dict)

import xml.etree.ElementTree as ET
import xml.dom.minidom
import xml.sax
import lxml.etree

# ruleid: python.lang.security.cwe-611.xml-external-entity
tree = xml.etree.ElementTree.parse(user_input)

# ruleid: python.lang.security.cwe-611.xml-external-entity
root = xml.etree.ElementTree.fromstring(xml_data)

# ruleid: python.lang.security.cwe-611.xml-external-entity
tree = lxml.etree.parse(uploaded_file)

# ruleid: python.lang.security.cwe-611.xml-external-entity
doc = xml.dom.minidom.parseString(xml_string)

# ruleid: python.lang.security.cwe-611.xml-external-entity
xml.sax.parseString(xml_data, handler)

# ok: python.lang.security.cwe-611.xml-external-entity
import defusedxml.ElementTree as SafeET
tree = SafeET.parse(user_input)

# ok: python.lang.security.cwe-611.xml-external-entity
import defusedxml.minidom
doc = defusedxml.minidom.parseString(xml_string)

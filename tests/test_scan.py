from pysigma import PySigma
from pysigma.signatures import sigma_string_to_regex

event = {
    'Data': [],
    'cats': 'good',
    'dogs': 'good',
    'dog_count': 2,
    'birds': 'many'
}


base_signature = """
title: sample signature
detection:
    true_expected: # dogs or dog_count
        - go?d
        - 2
    true_also_expected: # (dogs good or dogs ok) and cats good 
        dogs: 
            - good
            - ok
        cats: good
    true_cats_expected:
        cats: go*
    true_still_expected: # cats good or birds few
        - cats: good
        - birds: few
    false_expected: # frogs or trees
        - frogs
        - trees
    false_also_expected: # cats good and birds none
        cats: good
        birds: none
"""

complicated_condition = base_signature + """
    condition: (all of true_*) and (1 of *_expected) and (1 of true_*) and not all of them and (all of them or true_expected)
"""


def test_or_search():
    # Test a signature where the search block is just a list (or operation)
    # Also has an example of the ? wildcard embedded
    sigma = PySigma()
    sigma.add_signature(base_signature + "    condition: true_expected")
    assert len(sigma.check_events([event])) == 1


def test_value_or_search():
    # Test a signature where the search block has a list of values (or across those values)

    sigma = PySigma()
    sigma.add_signature(base_signature + "    condition: true_also_expected")
    assert len(sigma.check_events([event])) == 1


def test_value_wildcard_search():
    # has an example of the * wildcard embedded
    sigma = PySigma()
    sigma.add_signature(base_signature + "    condition: true_cats_expected")
    assert len(sigma.check_events([event])) == 1


def test_and_search():
    # Test a signature where the search block is just a map (and operation)
    sigma = PySigma()
    sigma.add_signature(base_signature + "    condition: true_still_expected")
    assert len(sigma.check_events([event])) == 1


def test_complicated_condition():
    sigma = PySigma()
    sigma.add_signature(complicated_condition)
    assert len(sigma.check_events([event])) == 1


def test_null_and_not_null():
    sigma = PySigma()
    sigma.add_signature("""
        title: sample signature
        detection:
            forbid:
                x: null
            filter:
                y: null
            condition: forbid and not filter
    """)

    assert len(sigma.check_events([{'y': 'found', 'Data': []}])) == 1
    assert len(sigma.check_events([{'z': 'found', 'Data': []}])) == 0
    assert len(sigma.check_events([{'y': 'found', 'x': 'also', 'Data': []}])) == 0


def test_substrings():
    # Is this what that part of the standard meant about list of strings anywhere?
    sigma = PySigma()
    sigma.add_signature("""        
        title: sample signature
        detection:
            signs:
                - "red things"
                - "blue things"
            condition: signs
    """)

    assert len(sigma.check_events([{'log': 'all sorts of red things and blue things were there', 'Data': []}])) == 1


def test_escaped_wildcards():
    sigma = PySigma()
    sigma.add_signature(r"""
        title: literal_star
        detection:
            field:
                x: a\*a
            condition: field
    """)
    sigma.add_signature(r"""
        title: literal_question
        detection:
            field:
                x: a\?a
            condition: field
    """)
    sigma.add_signature("""
        title: star
        detection:
            field:
                x: a*a
            condition: field
    """)
    sigma.add_signature("""
        title: question
        detection:
            field:
                x: a?a
            condition: field
    """)
    for rule in sigma.rules.values():
        print(rule.title)
        print(rule.get_all_searches()['field'].map_search)

    def alert_names(line):
        return set(alert['title'] for alert in sigma.check_events([{'x': line, 'Data': []}]))

    assert alert_names('a*ba') == {'star'}
    assert alert_names('aba') == {'star', 'question'}
    assert alert_names('a?a') == {'star', 'question', 'literal_question'}
    assert alert_names('a*a') == {'star', 'question', 'literal_star'}


def test_regex_transform():
    assert sigma_string_to_regex(r'.').pattern == r'\.'
    assert sigma_string_to_regex(r'*').pattern == r'.*'
    assert sigma_string_to_regex(r'?').pattern == r'.'
    assert sigma_string_to_regex(r'.\*').pattern == r'\.\*'
    assert sigma_string_to_regex(r'.\?').pattern == r'\.\?'
    assert sigma_string_to_regex(r'.\*abc').pattern == r'\.\*abc'
    assert sigma_string_to_regex(r'.\*abc*').pattern == r'\.\*abc.*'
    assert sigma_string_to_regex(r'.\*abc?').pattern == r'\.\*abc.'
    assert sigma_string_to_regex(r'.\*abc\?').pattern == r'\.\*abc\?'
    assert sigma_string_to_regex(r'.\*abc\\?').pattern == r'\.\*abc\\.'
    assert sigma_string_to_regex(r'.\*abc\\\?').pattern == r'\.\*abc\\\?'
    assert sigma_string_to_regex(r'a\a').fullmatch(r'a\a')
    assert sigma_string_to_regex(r'a\*a').fullmatch(r'a*a')
    assert sigma_string_to_regex(r'a*a').fullmatch(r'a a bunch of garbage a')


def test_1_of_them():
    # Make sure 1
    sigma = PySigma()
    sigma.add_signature("""        
        title: sample signature
        detection:
            a: ["a"]
            b: ["b"]
            condition: 1 of them
    """)

    assert len(sigma.check_events([{'log': 'a', 'Data': []}])) == 1
    assert len(sigma.check_events([{'log': 'b', 'Data': []}])) == 1
    assert len(sigma.check_events([{'log': 'ab', 'Data': []}])) == 1
    assert len(sigma.check_events([{'log': 'c', 'Data': []}])) == 0


def test_1_of_x():
    # Make sure 1
    sigma = PySigma()
    sigma.add_signature("""        
        title: sample signature
        detection:
            aa: ["aa"]
            ab: ["ab"]
            ba: ["ba"]
            bb: ["bb"]
            condition: 1 of a*
    """)

    assert len(sigma.check_events([{'log': 'aa', 'Data': []}])) == 1
    assert len(sigma.check_events([{'log': '1ab ba ca', 'Data': []}])) == 1
    assert len(sigma.check_events([{'log': 'ba', 'Data': []}])) == 0
    assert len(sigma.check_events([{'log': 'aabb', 'Data': []}])) == 1


def test_all_of_them():
    # Make sure 1
    sigma = PySigma()
    sigma.add_signature("""        
        title: sample signature
        detection:
            a: ["a"]
            b: ["b"]
            condition: all of them
    """)

    assert len(sigma.check_events([{'log': 'a', 'Data': []}])) == 0
    assert len(sigma.check_events([{'log': 'b', 'Data': []}])) == 0
    assert len(sigma.check_events([{'log': 'ab', 'Data': []}])) == 1
    assert len(sigma.check_events([{'log': 'bac', 'Data': []}])) == 1
    assert len(sigma.check_events([{'log': 'c', 'Data': []}])) == 0


def test_all_of_x():
    # Make sure 1
    sigma = PySigma()
    sigma.add_signature("""        
        title: sample signature
        detection:
            aa: ["aa"]
            ab: ["ab"]
            ba: ["ba"]
            bb: ["bb"]
            condition: all of a*
    """)

    assert len(sigma.check_events([{'log': 'aa', 'Data': []}])) == 0
    assert len(sigma.check_events([{'log': '1ab ba ca', 'Data': []}])) == 0
    assert len(sigma.check_events([{'log': 'ba', 'Data': []}])) == 0
    assert len(sigma.check_events([{'log': 'aabb', 'Data': []}])) == 1


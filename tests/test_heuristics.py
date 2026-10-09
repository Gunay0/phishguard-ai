from phishguard.heuristics import find_indicators, heuristic_risk

from phishguard.models import RiskLevel





def test_phishing_message():

    text = "URGENT: Your account has been suspended. Please send your password within 24 hours."

    indicators = find_indicators(text)



    assert len(indicators) > 0

    assert heuristic_risk(indicators, len(text)) == RiskLevel.HIGH





def test_normal_message():

    text = "Hi, lunch at 1pm tomorrow? See you at the usual place."

    indicators = find_indicators(text)



    assert heuristic_risk(indicators, len(text)) == RiskLevel.LOW





def test_empty_message():

    indicators = find_indicators("")



    assert indicators == []

    assert heuristic_risk(indicators, 0) == RiskLevel.UNKNOWN

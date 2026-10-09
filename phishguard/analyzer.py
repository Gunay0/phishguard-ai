from phishguard.heuristics import (

    detect_language,

    find_indicators,

    heuristic_risk,

)



from phishguard.url_analyzer import (

    extract_urls,

    analyze_url,

)



from phishguard.models import (

    AnalysisResult,

    RiskLevel,

)


def analyze_message(text: str) -> AnalysisResult:

    indicators = find_indicators(text)

    language = detect_language(text)

    risk = heuristic_risk(indicators, len(text))
    urls = extract_urls(text)

    url_findings = []



    for url in urls:

        url_findings.extend(analyze_url(url))

    url_score = sum(f.weight for f in url_findings)



    if url_score >= 15:

           url_risk = RiskLevel.HIGH
  
    elif url_score >= 8:

        url_risk = RiskLevel.MEDIUM

    elif url_score > 0:

        url_risk = RiskLevel.LOW

    else:

        url_risk = RiskLevel.UNKNOWN
    if risk == RiskLevel.HIGH or url_risk == RiskLevel.HIGH:

        final_risk = RiskLevel.HIGH

    elif risk == RiskLevel.MEDIUM or url_risk == RiskLevel.MEDIUM:

        final_risk = RiskLevel.MEDIUM

    elif risk == RiskLevel.LOW or url_risk == RiskLevel.LOW:

        final_risk = RiskLevel.LOW

    else:

        final_risk = RiskLevel.UNKNOWN
    return AnalysisResult(

        input_length=len(text),

        language=language,

        indicators=indicators,

        url_findings=url_findings,

        heuristic_risk=risk,

        final_risk=final_risk,

    )

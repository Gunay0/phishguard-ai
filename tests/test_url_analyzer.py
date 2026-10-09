from phishguard.url_analyzer import analyze_url





def test_embedded_credentials():

    findings = analyze_url("https://user:pass@example.com/login")

    assert any(f.rule_id == "embedded_credentials" for f in findings)





def test_normal_url():

    findings = analyze_url("https://example.com/login")

    assert not any(f.rule_id == "embedded_credentials" for f in findings)
def test_ip_address_url():

    from phishguard.url_analyzer import analyze_url



    findings = analyze_url("http://192.168.1.10/login")



    assert any(

        finding.rule_id == "ip_address_host"

        for finding in findings

    )
def test_long_url():

    url = "https://example.com/" + "a" * 130

    findings = analyze_url(url)



    assert any(

        f.rule_id == "long_url"

        for f in findings

    )
def test_insecure_http():

    findings = analyze_url("http://example.com/login")



    assert any(

        f.rule_id == "insecure_http"

        for f in findings

    )
def test_many_subdomains():

    url = "https://a.b.c.d.e.example.com/login"

    findings = analyze_url(url)



    assert any(

        f.rule_id == "many_subdomains"

        for f in findings

    )

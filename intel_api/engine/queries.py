"""Search queries per watched term. Shared by the background search jobs and the threat-intel collector,
so the API's stored results are exactly what the collector would have searched for."""


def news_query(term, term_type):
    if term_type == "vendor":
        return f'"{term}" (breach OR hacked OR compromised OR "security incident" OR vulnerability)'
    if term_type == "package":
        return f'"{term}" (PyPI OR npm OR package) (malicious OR compromised OR backdoor OR hijacked)'
    if term_type == "certificate_authority":
        return f'"{term}" certificate authority (distrust OR compromised OR revoked OR "root store")'
    return f'"{term}"'

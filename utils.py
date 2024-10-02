def standardize_service_name(service_name):
    """ Standardize common service names for CVE lookup. """
    service_map = {
        'http': 'http',
        'https': 'ssl',   # ssl or tls services might fall under https
        'ssh': 'ssh',
        'ftp': 'ftp',
        'smtp': 'smtp',
        'dns': 'dns',
        'ssl': 'https'    # Mapping ssl to https for correct lookup
    }
    return service_map.get(service_name.lower(), None)

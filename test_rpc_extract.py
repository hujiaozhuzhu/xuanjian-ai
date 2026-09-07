import re, json, os

js_files = [
    r'C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js',
    r'C:\Users\lenovo\xuanjian-ai\target-lab-temp\lab_sources\index.html',
    r'C:\Users\lenovo\xuanjian-ai\target-lab-temp\lab_sources\vuln5.php',
    r'C:\Users\lenovo\xuanjian-ai\target-lab-temp\lab_sources\vuln6.php',
]

for filepath in js_files:
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Find all fetch/ajax calls
        fetch_matches = re.findall(r'fetch\([\'"]([^"\']+)[\'"]', content)
        post_matches = re.findall(r'method:\s*[\'"]([^"\']+)[\'"]', content)
        url_matches = re.findall(r'url:\s*[\'"]([^"\']+)[\'"]', content)
        action_matches = re.findall(r'action:\s*[\'"]([^"\']+)[\'"]', content)
        
        # PHP endpoints
        php_endpoints = re.findall(r'\$_(?:GET|POST|REQUEST|COOKIE|FILES)\[[\'"]([^"\']+)[\'"]]', content)
        
        # HTML form actions
        form_actions = re.findall(r'<form[^>]*action=[\'"]([^"\']+)[\'"]', content)
        
        print(f'File: {os.path.basename(filepath)}')
        print(f'  fetch endpoints: {fetch_matches}')
        print(f'  HTTP methods: {post_matches}')
        print(f'  URL patterns: {url_matches}')
        print(f'  PHP params: {php_endpoints}')
        print(f'  Form actions: {form_actions}')
        print()

# Java endpoint analysis from source files
print("\n=== Java Vulnerable Endpoints (from source code) ===")
java_files = [
    r'C:\Users\lenovo\xuanjian-ai\target-lab-temp\lab_sources\java\Vuln1NativeDeserializationController.java',
    r'C:\Users\lenovo\xuanjian-ai\target-lab-temp\lab_sources\java\Vuln2FastjsonController.java',
    r'C:\Users\lenovo\xuanjian-ai\target-lab-temp\lab_sources\java\Vuln3JacksonController.java',
    r'C:\Users\lenovo\xuanjian-ai\target-lab-temp\lab_sources\java\Vuln4ShiroController.java',
]

for filepath in java_files:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract RequestMapping paths
    mappings = re.findall(r'@(?:Get|Post|Put|Delete|Patch)?Mapping\s*\(\s*(?:value\s*=)?[\'"]([^"\']+)[\'"]', content)
    class_mapping = re.findall(r'@RequestMapping\s*\(\s*[\'"]([^"\']+)[\'"]', content)
    
    print(f'{os.path.basename(filepath)}:')
    print(f'  Class mapping: {class_mapping}')
    print(f'  Method mappings: {mappings}')
    
    # Find vulnerable sinks
    sinks = []
    if 'readObject' in content: sinks.append('ObjectInputStream.readObject()')
    if 'parseObject' in content: sinks.append('JSON.parseObject()')
    if 'enableDefaultTyping' in content: sinks.append('enableDefaultTyping()')
    if 'unserialize' in content: sinks.append('unserialize()')
    if 'pickle.loads' in content: sinks.append('pickle.loads()')
    print(f'  Sinks: {sinks}')
    print()

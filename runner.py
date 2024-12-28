class CodeScanner:
    def __init__(self, provider):
        self.provider = provider
        
    def scan_file(self, file_path):
       
        with open(file_path, 'r') as f:
            code = f.read()
            
        from app.routes import analyze_with_openai, analyze_with_gemini
        analysis = analyze_with_openai(code) if self.provider == 'openai' else analyze_with_gemini(code)
        
        return ScanResult(analysis)

class ScanResult:
    def __init__(self, raw_output):
        self.raw_output = raw_output
        self.issues = self._parse_issues(raw_output)
    
    def _parse_issues(self, raw_output):
      c
        from app.routes import parse_ai_analysis
        results = parse_ai_analysis(raw_output)
        return self._convert_to_issues(results)
    
    def _convert_to_issues(self, results):
        issues = []
        for category, items in results.items():
            for item in items:
                issues.append(Issue(
                    type=category,
                    severity=item['severity'],
                    title=item.get('title', ''),
                    description=item.get('description', ''),
                    recommendation=item.get('recommendation', '')
                ))
        return issues

class Issue:
    def __init__(self, type, severity, title, description, recommendation):
        self.type = type
        self.severity = severity
        self.title = title
        self.description = description
        self.recommendation = recommendation 
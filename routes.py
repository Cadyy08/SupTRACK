from flask import Blueprint, render_template, request, jsonify, send_from_directory
import tempfile
import os
import json
import subprocess
import sys
from google.generativeai import GenerativeModel
import google.generativeai as genai
from openai import OpenAI
from config import Config
from werkzeug.utils import secure_filename
from app.core.runner import CodeScanner

main = Blueprint('main', __name__)


client = OpenAI(api_key=Config.OPENAI_API_KEY)
genai.configure(api_key=Config.GEMINI_API_KEY)


UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
SOURCE_FOLDER = os.path.join(UPLOAD_FOLDER, 'source')
SURVEY_FOLDER = os.path.join(UPLOAD_FOLDER, 'surveys')
ALLOWED_EXTENSIONS = {'csv'}


os.makedirs(SOURCE_FOLDER, exist_ok=True)
os.makedirs(SURVEY_FOLDER, exist_ok=True)

def analyze_with_openai(code):
    prompt = f"""Analyze this code for vulnerabilities and provide a structured response.
Follow this EXACT format (keep the exact headers and structure):

SECURITY VULNERABILITIES:
(HIGH): [Issue title here]
[Description here]
Recommendation: [MITIGATIONS LINKED with SECURITY VULNERABILITIES from MIITRE.org]
CVE: [list all CVE numbers separated by comma]
APT-GROUPS:[list all APT Group numbers separated by comma]
ATTACK NAME: [ATTACK NAME here]
SUPPLYCHAIN ATTACK: [put linked supplychain cybersecurity attack if any with attack name and list down the affected companies separated by comma]
LINKED CODE: [put the vulnerable line of code realted to the security vulnerability here]

(MEDIUM): [Issue title here]
[Description here]
Recommendation: [MITIGATIONS LINKED with SECURITY VULNERABILITIES from MIITRE.org]
CVE: [list all CVE numbers separated by comma]
APT-GROUPS:[list all APT Group numbers separated by comma]
ATTACK NAME: [ATTACK NAME here]
SUPPLYCHAIN ATTACK: [put linked supplychain cybersecurity attack if any with attack name and list down the affected companies separated by comma]
LINKED CODE: [put the vulnerable line of code realted to the security vulnerability here]

CODE QUALITY:
(HIGH): [Issue title here]
[Description here]
Recommendation: [Fix here]

(MEDIUM): [Issue title here]
[Description here]
Recommendation: [Fix here]

BEST PRACTICES:
(HIGH): [Issue title here]
[Description here]
Recommendation: [Fix here]

Here's the code to analyze:
{code}
"""
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system", 
                            "content": "You are a code analyzer. Always respond in the exact format specified, using the exact headers SECURITY VULNERABILITIES, CODE QUALITY, CVE NUMBERS LINKED WITH SECURITY VULNERABILITIES,APT GROUPS LINKED WITH THE CVE NUMBERS FROM HTTPS://ATTACK.MITRE.ORG,LINKED ATTACK NAME FROM HTTPS://ATTACK.MITRE.ORG ,IDENTIFY IF SECURITY VULNERABILITIES LINKED TO A SUPPLYCHAIN CYBERSECURITY ATTACK, and MITIGATIONS LINKED SECURITY VULNERABILITIES FROM HTTPS://ATTACK.MITRE.ORG. Always include severity levels (HIGH), (MEDIUM), or (LOW) before each issue."

            },
            {"role": "user", "content": prompt}
        ],
        temperature=0.5  # Lower temperature for more consistent outcomes
    )
    return response.choices[0].message.content

def analyze_with_gemini(code):
    model = GenerativeModel('gemini-pro')
    prompt = f"""Analyze this code for vulnerabilities and provide a structured response.
Follow this EXACT format (keep the exact headers and structure):

SECURITY VULNERABILITIES:
(HIGH): [Issue title here]
[Description here]
Recommendation: [Fix here]

(MEDIUM): [Issue title here]
[Description here]
Recommendation: [Fix here]

CODE QUALITY:
(HIGH): [Issue title here]
[Description here]
Recommendation: [Fix here]

(MEDIUM): [Issue title here]
[Description here]
Recommendation: [Fix here]

BEST PRACTICES:
(HIGH): [Issue title here]
[Description here]
Recommendation: [Fix here]

Here's the code to analyze:
{code}
"""
    
    response = model.generate_content(
        prompt,
        generation_config={
            'temperature': 0.5, 
        }
    )
    return response.text

def parse_ai_analysis(raw_analysis):
    """Parse and structure the AI analysis results"""
    try:
        # Initialize categories
        categories = {
            'vulnerabilities': [],
            'code_quality': [],
            'best_practices': []
        }
        
        current_category = None
        current_issue = {}
        
     
        lines = raw_analysis.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Detect severity level
            severity_level = None
            if '(HIGH)' in line.upper():
                severity_level = 'high'
            elif '(MEDIUM)' in line.upper():
                severity_level = 'medium'
            elif '(LOW)' in line.upper():
                severity_level = 'low'
                
            # Identify categories
            if 'SECURITY VULNERABILITIES' in line.upper():
                current_category = 'vulnerabilities'
                continue
            elif 'CODE QUALITY' in line.upper():
                current_category = 'code_quality'
                continue
            elif 'BEST PRACTICES' in line.upper():
                current_category = 'best_practices'
                continue
                
            if current_category and severity_level:
              
                current_issue = {
                    'severity': severity_level,
                    'title': line.split(':', 1)[1].strip() if ':' in line else line,
                    'description': '',
                    'recommendation': ''
                }
                categories[current_category].append(current_issue)
            elif current_issue:
              
                if line.lower().startswith('recommendation:'):
                    current_issue['recommendation'] = line.split(':', 1)[1].strip()
                else:
                    current_issue['description'] += line + ' '
        
        return categories
        
    except Exception as e:
        print(f"Error parsing AI analysis: {str(e)}")
        return None

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/scan', methods=['POST'])
def scan_code():
    try:
        code = request.form.get('code')
        provider = request.form.get('provider')
        
        # Create temporary file for scanning
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        try:
            if provider in ['openai', 'gemini']:
               
                scanner = CodeScanner(provider=provider)
                
              
                scan_results = scanner.scan_file(temp_path)
                
                
                structured_analysis = {
                    'vulnerabilities': [],
                    'code_quality': [],
                    'best_practices': []
                }
                
                for issue in scan_results.issues:
                    category = 'vulnerabilities' if issue.type == 'security' else \
                              'code_quality' if issue.type == 'quality' else 'best_practices'
                    
                    structured_analysis[category].append({
                        'severity': issue.severity.lower(),
                        'title': issue.title,
                        'description': issue.description,
                        'recommendation': issue.recommendation
                    })
                
                return jsonify({
                    'success': True,
                    'results': {
                        'structured_analysis': structured_analysis,
                        'raw_analysis': scan_results.raw_output,
                        'provider': provider
                    }
                })
            
           
            cmd = [sys.executable, '-m', 'bandit', '-f', 'json', '-ll', '-i', '-r', temp_path]
            process = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            scan_data = json.loads(process.stdout if process.stdout else '{"results": [], "metrics": {}}')
            vulnerabilities = []
            
            for issue in scan_data.get('results', []):
                vulnerabilities.append({
                    'severity': issue.get('issue_severity', 'UNKNOWN').upper(),
                    'description': issue.get('issue_text', ''),
                    'line_number': issue.get('line_number', 0),
                    'code_snippet': issue.get('code', ''),
                    'source': 'Bandit',
                    'confidence': issue.get('issue_confidence', 'UNKNOWN').upper()
                })

            
            ai_suggestion = ""
            if vulnerabilities:
                ai_suggestion = "Consider using AI analysis (OpenAI/Gemini) for deeper insights into these vulnerabilities."

            os.unlink(temp_path)

            return jsonify({
                'success': True,
                'results': {
                    'vulnerabilities': vulnerabilities,
                    'provider': 'bandit',
                    'ai_suggestion': ai_suggestion,
                    'summary': f"Found {len(vulnerabilities)} potential security issues."
                }
            })

        finally:
            
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@main.route('/upload_survey', methods=['POST'])
def upload_survey():
    try:
        if 'survey_file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})
        
        file = request.files['survey_file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if not file.filename.endswith('.csv'):
            return jsonify({'success': False, 'error': 'Only CSV files are allowed'})
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(SURVEY_FOLDER, filename)
        file.save(filepath)
        
        return jsonify({
            'success': True,
            'message': 'Survey file uploaded successfully',
            'filename': filename
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}) 

@main.route('/save_file', methods=['POST'])
def save_file():
    try:
        file_name = request.form.get('file_name')
        content = request.form.get('content')
        file_type = request.form.get('file_type', 'source')
        
        if not file_name:
            return jsonify({'success': False, 'error': 'File name is required'})
            
        
        save_dir = os.path.join(UPLOAD_FOLDER, 'surveys' if file_type == 'survey' else 'source')
        os.makedirs(save_dir, exist_ok=True)
        
        file_path = os.path.join(save_dir, secure_filename(file_name))
        
        with open(file_path, 'w') as f:
            f.write(content)
            
        return jsonify({
            'success': True,
            'message': 'File saved successfully',
            'file_type': file_type,
            'file_name': file_name
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@main.route('/download_file/<file_type>/<file_name>')
def download_file(file_type, file_name):
    try:
        directory = os.path.join(UPLOAD_FOLDER, 'surveys' if file_type == 'survey' else 'source')
        return send_from_directory(directory, secure_filename(file_name))
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@main.route('/delete_file/<file_type>/<file_name>')
def delete_file(file_type, file_name):
    try:
        directory = os.path.join(UPLOAD_FOLDER, 'surveys' if file_type == 'survey' else 'source')
        file_path = os.path.join(directory, secure_filename(file_name))
        
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({'success': True})
        
        return jsonify({'success': False, 'error': 'File not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}) 

@main.route('/list_files/<file_type>')
def list_files(file_type):
    try:
        directory = os.path.join(UPLOAD_FOLDER, 'surveys' if file_type == 'survey' else 'source')
        if not os.path.exists(directory):
            return jsonify({'files': []})
            
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}) 
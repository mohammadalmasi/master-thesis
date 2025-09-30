import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  AlertTriangle, 
  CheckCircle, 
  Info, 
  Download, 
  ArrowLeft,
  FileText,
  Code,
  Shield,
  AlertCircle,
  Bug
} from 'lucide-react';
import config from '../config.js';

interface Vulnerability {
  file_path: string;
  line_number: number;
  vulnerability_type: string;
  description: string;
  severity: string;
  code_snippet: string;
  remediation: string;
  confidence: number;
  rule_key?: string;
  cwe_references?: string[];
  owasp_references?: string[];
  sq_category?: string;
}

interface ScanResults {
  vulnerabilities?: Vulnerability[];
  summary?: {
    total_vulnerabilities: number;
    high_severity: number;
    medium_severity: number;
    low_severity: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
  // Enhanced API fields
  total_issues: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_timestamp: string;
  source?: string;
  scan_type?: string;
  scannerType?: 'sql' | 'xss' | 'command' | 'csrf';
  analysisMode?: 'static' | 'ml';
  image_url?: string;
  upload_id?: string;
  warning?: string;
  compliance?: {
    cwe_distribution: Record<string, number>;
    owasp_top10_distribution: Record<string, number>;
  };
  file_name?: string;
  highlighted_code?: string;
  original_code?: string;
}

const Results: React.FC = () => {
  const navigate = useNavigate();
  const [results, setResults] = useState<ScanResults | null>(null);
  const [scanInput, setScanInput] = useState<any>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  useEffect(() => {
    const storedResults = localStorage.getItem('scanResults');
    const storedInput = localStorage.getItem('scanInput');
    
    if (storedResults) {
      setResults(JSON.parse(storedResults));
    }
    
    if (storedInput) {
      setScanInput(JSON.parse(storedInput));
    }
    
    // If no results found, redirect to scanner
    if (!storedResults) {
      navigate('/scanner');
    }
  }, [navigate]);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'text-danger-600 bg-danger-50 border-danger-200';
      case 'medium':
        return 'text-warning-600 bg-warning-50 border-warning-200';
      case 'low':
        return 'text-success-600 bg-success-50 border-success-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-danger-600" />;
      case 'medium':
        return <AlertCircle className="h-5 w-5 text-warning-600" />;
      case 'low':
        return <Info className="h-5 w-5 text-success-600" />;
      default:
        return <Info className="h-5 w-5 text-gray-600" />;
    }
  };

  const getScannerTitle = () => {
    if (results?.scannerType === 'xss') {
      return 'XSS Security Scan Results';
    } else if (results?.scannerType === 'command') {
      return 'Command Injection Security Scan Results';
    } else if (results?.scannerType === 'csrf') {
      return 'CSRF Security Scan Results';
    }
    return 'SQL Injection Security Scan Results';
  };

  const getScannerIcon = () => {
    if (results?.scannerType === 'xss') {
      return <Shield className="h-8 w-8 text-primary-600 mr-3" />;
    } else if (results?.scannerType === 'command') {
      return <AlertTriangle className="h-8 w-8 text-primary-600 mr-3" />;
    } else if (results?.scannerType === 'csrf') {
      return <Shield className="h-8 w-8 text-primary-600 mr-3" />;
    }
    return <Bug className="h-8 w-8 text-primary-600 mr-3" />;
  };

  const filteredVulnerabilities = results?.vulnerabilities?.filter(vuln => {
    if (filterSeverity === 'all') return true;
    return vuln.severity.toLowerCase() === filterSeverity.toLowerCase();
  }) || [];

  const downloadReport = async () => {
    if (!results) return;
    
    try {
      // ML report path mirrors static: if ML, call ML endpoint
      if (results.analysisMode === 'ml') {
        const mlPayload: any = {
          upload_id: results.upload_id,
          image_url: results.image_url,
          filename: results.file_name || scanInput?.filename || 'code.py',
          original_code: results.original_code || scanInput?.content || '',
          scanner_type: results.scannerType || 'ml'
        };

        const mlResp = await fetch(`${config.API_BASE_URL}/api/generate-ml-report`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(mlPayload)
        });
        if (!mlResp.ok) throw new Error('Failed to generate ML report');
        const blob = await mlResp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const cd = mlResp.headers.get('Content-Disposition');
        let filename = cd && /filename="?([^"]+)"?/.exec(cd)?.[1] || `ml-security-report-${new Date().toISOString().split('T')[0]}.docx`;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        return;
      }

      const reportData = {
        vulnerabilities: results.vulnerabilities,
        summary: results.summary,
        scan_info: {
          scan_timestamp: new Date().toISOString(),
          input_type: scanInput?.type || 'unknown',
          file_name: scanInput?.filename || scanInput?.type || 'N/A',
          scanner_type: results.scannerType || 'sql'
        },
        original_code: results.original_code || ''
      };

      // Get JWT token from localStorage
      const headers: HeadersInit = {
        'Content-Type': 'application/json'
      };

      // Choose the appropriate report endpoint based on scanner type
      let endpoint: string;
      if (results.scannerType === 'xss') {
        endpoint = '/api/generate-xss-report';
      } else if (results.scannerType === 'command') {
        endpoint = '/api/generate-command-injection-report';
      } else if (results.scannerType === 'csrf') {
        endpoint = '/api/generate-csrf-report';
      } else {
        endpoint = '/api/generate-sql-injection-report';
      }

      const response = await fetch(`${config.API_BASE_URL}${endpoint}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(reportData),
      });

      if (!response.ok) {
        throw new Error('Failed to generate report');
      }

      // The API now returns the file directly
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      
      // Extract filename from response headers or use default
      const contentDisposition = response.headers.get('Content-Disposition');
      let scanType: string;
      if (results.scannerType === 'xss') {
        scanType = 'xss';
      } else if (results.scannerType === 'command') {
        scanType = 'command-injection';
      } else if (results.scannerType === 'csrf') {
        scanType = 'csrf';
      } else {
        scanType = 'sql-injection';
      }
      let filename = `${scanType}-security-report.docx`;
      
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="?([^"]+)"?/);
        if (match) {
          filename = match[1];
        }
      } else {
        // Generate filename with timestamp
        const timestamp = new Date().toISOString().split('T')[0];
        filename = `${scanType}-security-report-${timestamp}.docx`;
      }
      
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download error:', error);
      // Fallback to JSON if Word generation fails
      const reportData = {
        scan_timestamp: new Date().toISOString(),
        input_type: scanInput?.type || 'unknown',
        file_name: scanInput?.filename || 'N/A',
        scanner_type: results?.scannerType || 'sql',
        summary: results?.summary,
        vulnerabilities: results?.vulnerabilities
      };

      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const scanType = results?.scannerType === 'xss' ? 'xss' : 
                      results?.scannerType === 'command' ? 'command-injection' : 
                      results?.scannerType === 'csrf' ? 'csrf' : 'sql-injection';
      a.download = `${scanType}-security-report-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  if (!results) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="loading-spinner mx-auto mb-4"></div>
          <p className="text-gray-600">Loading scan results...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Link
                to="/scanner"
                className="flex items-center text-primary-600 hover:text-primary-700 transition-colors duration-200"
              >
                <ArrowLeft className="h-5 w-5 mr-2" />
                Back to Scanner
              </Link>
              <div className="h-6 w-px bg-gray-300"></div>
              <h1 className="text-2xl md:text-3xl font-bold text-gray-900">
                {getScannerTitle()}
              </h1>
            </div>
            
            <button
              onClick={downloadReport}
              className="btn-primary flex items-center"
            >
              <Download className="h-4 w-4 mr-2" />
              Download Report
            </button>
          </div>
          
          <div className="mt-4 text-sm text-gray-600">
            <p>
              <strong>Source:</strong> {scanInput?.filename || scanInput?.type || 'N/A'} •
                                <strong className="ml-2">Scanner Type:</strong> {
                    results.scannerType === 'xss' ? 'XSS' : 
                    results.scannerType === 'command' ? 'Command Injection' : 
                    results.scannerType === 'csrf' ? 'CSRF' : 'SQL Injection'
                  } • <strong className="ml-2">Mode:</strong> {results.analysisMode === 'ml' ? 'ML' : 'Static'} •
              <strong className="ml-2">Scanned:</strong> {new Date().toLocaleString()}
            </p>
          </div>
        </div>

        {/* Summary Cards */}
        {results.analysisMode === 'ml' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                {getScannerIcon()}
                <div>
                  <p className="text-sm font-medium text-gray-600">Analysis Type</p>
                  <p className="text-2xl font-bold text-gray-900">ML Analysis</p>
                </div>
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <Code className="h-8 w-8 text-primary-600 mr-3" />
                <div>
                  <p className="text-sm font-medium text-gray-600">Visualization</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {results.image_url ? 'Generated' : 'Not Available'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                {getScannerIcon()}
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Issues</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {results.total_issues || results.summary?.total_vulnerabilities || 0}
                  </p>
                </div>
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <AlertTriangle className="h-8 w-8 text-danger-600 mr-3" />
                <div>
                  <p className="text-sm font-medium text-gray-600">High Severity</p>
                  <p className="text-2xl font-bold text-danger-600">
                    {results.high_severity || results.summary?.high_severity || 0}
                  </p>
                </div>
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <AlertCircle className="h-8 w-8 text-warning-600 mr-3" />
                <div>
                  <p className="text-sm font-medium text-gray-600">Medium Severity</p>
                  <p className="text-2xl font-bold text-warning-600">
                    {results.medium_severity || results.summary?.medium_severity || 0}
                  </p>
                </div>
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <Info className="h-8 w-8 text-success-600 mr-3" />
                <div>
                  <p className="text-sm font-medium text-gray-600">Low Severity</p>
                  <p className="text-2xl font-bold text-success-600">
                    {results.low_severity || results.summary?.low_severity || 0}
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Filters - Only show for static analysis */}
        {results.analysisMode !== 'ml' && (
          <div className="bg-white rounded-lg shadow p-6 mb-8">
            <div className="flex flex-wrap items-center gap-4">
              <h3 className="text-lg font-semibold text-gray-900">Filter by Severity:</h3>
              <div className="flex space-x-2">
                {['all', 'high', 'medium', 'low'].map((severity) => {
                  const getCount = (sev: string) => {
                    switch (sev) {
                      case 'high':
                        return results.high_severity || results.summary?.high_severity || 0;
                      case 'medium':
                        return results.medium_severity || results.summary?.medium_severity || 0;
                      case 'low':
                        return results.low_severity || results.summary?.low_severity || 0;
                      default:
                        return results.total_issues || results.summary?.total_vulnerabilities || 0;
                    }
                  };
                  
                  return (
                    <button
                      key={severity}
                      onClick={() => setFilterSeverity(severity)}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                        filterSeverity === severity
                          ? 'bg-primary-600 text-white'
                          : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                      }`}
                    >
                      {severity.charAt(0).toUpperCase() + severity.slice(1)}
                      {severity !== 'all' && (
                        <span className="ml-1 text-xs">
                          ({getCount(severity)})
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* ML Visualization */}
        {results.analysisMode === 'ml' && results.image_url && (
          <div className="bg-white rounded-lg shadow mb-8">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <Code className="h-5 w-5 mr-2" />
                ML Visualization
              </h3>
              <p className="text-sm text-gray-600 mt-1">
                Generated by the LSTM-based analyzer from Atiqullah Ahmadzai’s project.
              </p>
            </div>
            <div className="p-6">
              <img src={`${config.API_BASE_URL}${results.image_url}`} alt="ML Visualization" className="w-full border rounded" />
            </div>
          </div>
        )}

        {/* Highlighted Source Code */}
        {results.analysisMode !== 'ml' && results.highlighted_code && (
          <div className="bg-white rounded-lg shadow mb-8">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <Code className="h-5 w-5 mr-2" />
                Source Code Analysis
              </h3>
              <p className="text-sm text-gray-600 mt-1">
                Vulnerable code sections are highlighted in red. 
                {results.scannerType === 'xss' 
                  ? ' XSS vulnerabilities are marked for review.'
                  : results.scannerType === 'command'
                  ? ' Command injection vulnerabilities are marked for review.'
                  : results.scannerType === 'csrf'
                  ? ' CSRF vulnerabilities are marked for review.'
                  : ' SQL injection vulnerabilities are marked for review.'
                }
              </p>
            </div>
            <div className="p-6">
              <div className="rounded-lg overflow-hidden border border-gray-300 shadow-inner">
                {/* Code Editor Header */}
                <div className="bg-gray-800 px-4 py-3 flex items-center justify-between border-b border-gray-700">
                  <div className="flex items-center space-x-3">
                    <FileText className="h-4 w-4 text-gray-300" />
                    <span className="text-gray-200 text-sm font-medium">
                      {results.file_name || scanInput?.filename || 'scanned_code.py'}
                    </span>
                    <span className="text-xs text-gray-400 bg-gray-700 px-2 py-1 rounded">
                      {results.scannerType === 'xss' ? 'XSS Analysis' : 
                       results.scannerType === 'command' ? 'Command Injection Analysis' : 
                       results.scannerType === 'csrf' ? 'CSRF Analysis' : 'SQL Injection Analysis'}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="flex space-x-1">
                      <div className="w-3 h-3 rounded-full bg-red-500"></div>
                      <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                      <div className="w-3 h-3 rounded-full bg-green-500"></div>
                    </div>
                  </div>
                </div>
                
                {/* Code Content */}
                <div className="bg-gray-900">
                  <div className="flex">
                    {/* Line Numbers */}
                    <div className="bg-gray-800 px-3 py-4 text-right text-gray-400 text-sm font-mono border-r border-gray-700 select-none">
                      {results.original_code?.split('\n').map((_, index) => (
                        <div key={index} className="leading-6">
                          {index + 1}
                        </div>
                      ))}
                    </div>
                    
                    {/* Code with Highlighting */}
                    <div className="flex-1 overflow-x-auto">
                      <pre 
                        className="text-sm text-gray-100 font-mono leading-6 code-content p-4"
                        dangerouslySetInnerHTML={{ __html: results.highlighted_code }}
                        style={{
                          whiteSpace: 'pre',
                          margin: 0,
                          padding: '1rem',
                          textAlign: 'left',
                          fontFamily: '"Fira Code", Monaco, "Cascadia Code", "Roboto Mono", monospace',
                          tabSize: 2,
                          overflowWrap: 'normal'
                        }}
                      />
                      <style>{`
                        .code-content .vuln {
                          background-color: #dc2626 !important;
                          color: #ffffff !important;
                          padding: 2px 4px;
                          border-radius: 3px;
                          font-weight: bold;
                          cursor: pointer;
                        }
                        .code-content .vuln:hover {
                          background-color: #b91c1c !important;
                        }
                        .code-content .xss-vuln {
                          background-color: #dc2626 !important;
                          color: #ffffff !important;
                          padding: 2px 4px;
                          border-radius: 3px;
                          font-weight: bold;
                          cursor: pointer;
                        }
                        .code-content .xss-vuln:hover {
                          background-color: #b91c1c !important;
                        }
                        
                        /* SQL Injection vulnerability highlighting */
                        .code-content .sql-injection-vuln-high {
                          background-color: #dc2626 !important;
                          color: #ffffff !important;
                          padding: 2px 4px;
                          border-radius: 3px;
                          font-weight: bold;
                          cursor: pointer;
                        }
                        .code-content .sql-injection-vuln-high:hover {
                          background-color: #b91c1c !important;
                        }
                        
                        .code-content .sql-injection-vuln-medium {
                          background-color: #f59e0b !important;
                          color: #000000 !important;
                          padding: 2px 4px;
                          border-radius: 3px;
                          font-weight: bold;
                          cursor: pointer;
                        }
                        .code-content .sql-injection-vuln-medium:hover {
                          background-color: #d97706 !important;
                        }
                        
                        .code-content .sql-injection-vuln-low {
                          background-color: #10b981 !important;
                          color: #000000 !important;
                          padding: 2px 4px;
                          border-radius: 3px;
                          font-weight: bold;
                          cursor: pointer;
                        }
                        .code-content .sql-injection-vuln-low:hover {
                          background-color: #059669 !important;
                        }
                        
                        /* XSS vulnerability highlighting */
                        .code-content .xss-vuln-high {
                          background-color: #dc2626 !important;
                          color: #ffffff !important;
                          padding: 2px 4px;
                          border-radius: 3px;
                          font-weight: bold;
                          cursor: pointer;
                        }
                        .code-content .xss-vuln-high:hover {
                          background-color: #b91c1c !important;
                        }
                        
                        .code-content .xss-vuln-medium {
                          background-color: #f59e0b !important;
                          color: #000000 !important;
                          padding: 2px 4px;
                          border-radius: 3px;
                          font-weight: bold;
                          cursor: pointer;
                        }
                        .code-content .xss-vuln-medium:hover {
                          background-color: #d97706 !important;
                        }
                        
                        .code-content .xss-vuln-low {
                          background-color: #10b981 !important;
                          color: #000000 !important;
                          padding: 2px 4px;
                          border-radius: 3px;
                          font-weight: bold;
                          cursor: pointer;
                        }
                        .code-content .xss-vuln-low:hover {
                          background-color: #059669 !important;
                        }
                      `}</style>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Vulnerabilities List - Only show for static analysis */}
        {results.analysisMode !== 'ml' && (
          <div className="space-y-6">
            {filteredVulnerabilities.length === 0 ? (
              <div className="bg-white rounded-lg shadow p-8 text-center">
                <CheckCircle className="h-16 w-16 text-success-600 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  {filterSeverity === 'all' ? 'No Vulnerabilities Found' : `No ${filterSeverity} Severity Issues`}
                </h3>
                <p className="text-gray-600">
                  {filterSeverity === 'all' 
                    ? `Great! Your code appears to be secure from ${
                        results.scannerType === 'xss' ? 'XSS' : 
                        results.scannerType === 'command' ? 'command injection' : 
                        results.scannerType === 'csrf' ? 'CSRF' : 'SQL injection'
                      } vulnerabilities.`
                    : `There are no ${filterSeverity} severity vulnerabilities in your code.`
                  }
                </p>
              </div>
            ) : (
              filteredVulnerabilities.map((vulnerability, index) => (
                <div key={index} className="bg-white rounded-lg shadow overflow-hidden">
                  <div 
                    className={`p-6 border-l-4 ${getSeverityColor(vulnerability.severity).replace('bg-', 'border-').replace('-50', '-500')}`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        {getSeverityIcon(vulnerability.severity)}
                        <div className="flex-1">
                          <h3 className="text-lg font-semibold text-gray-900 mb-1">
                            {results.scannerType === 'xss' ? 'XSS Vulnerability' : 
                             results.scannerType === 'command' ? 'Command Injection Vulnerability' : 
                             results.scannerType === 'csrf' ? 'CSRF Vulnerability' : 'SQL Injection Vulnerability'} - Line {vulnerability.line_number}
                          </h3>
                          <p className="text-gray-600 mb-4">
                            {vulnerability.description}
                          </p>
                          
                          {/* Vulnerability Details */}
                          <div className="space-y-3">
                            
                            {vulnerability.cwe_references && vulnerability.cwe_references.length > 0 && (
                              <div>
                                <h4 className="font-medium text-gray-900 mb-2">CWE References:</h4>
                                <div className="flex flex-wrap gap-2">
                                  {vulnerability.cwe_references.map((cwe, idx) => (
                                    <span key={idx} className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                                      CWE-{cwe}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                            
                            {vulnerability.owasp_references && vulnerability.owasp_references.length > 0 && (
                              <div>
                                <h4 className="font-medium text-gray-900 mb-2">OWASP References:</h4>
                                <div className="flex flex-wrap gap-2">
                                  {vulnerability.owasp_references.map((owasp, idx) => (
                                    <span key={idx} className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded">
                                      {owasp}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(vulnerability.severity)}`}>
                          {vulnerability.severity.toUpperCase()}
                        </span>
                        <span className="text-sm text-gray-500">
                          {Math.round(vulnerability.confidence * 100)}% confidence
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* ML Analysis Info */}
        {results.analysisMode === 'ml' && (
          <div className="bg-white rounded-lg shadow p-8 text-center">
            <Code className="h-16 w-16 text-primary-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-900 mb-2">
              Machine Learning Analysis Complete
            </h3>
            <p className="text-gray-600 mb-4">
              The ML analysis has been performed using LSTM-based models from Atiqullah Ahmadzai's project.
              {results.warning && (
                <span className="block mt-2 text-yellow-600 font-medium">
                  {results.warning}
                </span>
              )}
            </p>
            <p className="text-sm text-gray-500">
              Check the visualization above for detailed analysis results.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Results; 
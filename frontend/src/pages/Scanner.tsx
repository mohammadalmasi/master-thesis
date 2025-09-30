import React, { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { 
  Upload, 
  Link as LinkIcon, 
  Code, 
  AlertTriangle, 
  CheckCircle, 
  Loader2,
  FileText,
  X,
  Shield,
  Bug
} from 'lucide-react';
import toast from 'react-hot-toast';
import config from '../config.js';
import { fetchScannerConfig, isScannerEnabled, ScannerConfig } from '../services/configService';

interface ScanInput {
  type: 'url' | 'file' | 'code';
  content: string;
  filename?: string;
}

type ScannerType = 'sql' | 'xss' | 'command' | 'csrf';

const Scanner: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'url' | 'file' | 'code'>('code');
  const [scannerType, setScannerType] = useState<ScannerType>('sql');
  const [isScanning, setIsScanning] = useState(false);
  const [analysisMode, setAnalysisMode] = useState<'static' | 'ml'>('static');
  const [scannerConfig, setScannerConfig] = useState<ScannerConfig | null>(null);
  const [isLoadingConfig, setIsLoadingConfig] = useState(true);
  const [scanInput, setScanInput] = useState<ScanInput>({
    type: 'code',
    content: '',
    filename: ''
  });
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);

  // Fetch scanner configuration on component mount
  useEffect(() => {
    const loadConfig = async () => {
      try {
        const config = await fetchScannerConfig();
        setScannerConfig(config);
        
        // Set the first enabled scanner as default
        if (isScannerEnabled(config, 'sql')) {
          setScannerType('sql');
        } else if (isScannerEnabled(config, 'xss')) {
          setScannerType('xss');
        } else if (isScannerEnabled(config, 'command')) {
          setScannerType('command');
        } else if (isScannerEnabled(config, 'csrf')) {
          setScannerType('csrf');
        }
      } catch (error) {
        console.error('Failed to load scanner configuration:', error);
        toast.error('Failed to load scanner configuration');
      } finally {
        setIsLoadingConfig(false);
      }
    };
    
    loadConfig();
  }, []);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const validFiles = acceptedFiles.filter(file => {
      const validExtensions = ['.py', '.js', '.php', '.java', '.cs', '.ts', '.jsx', '.tsx'];
      const hasValidExtension = validExtensions.some(ext => file.name.toLowerCase().endsWith(ext));
      
      if (!hasValidExtension) {
        toast.error(`${file.name} is not a supported file type`);
        return false;
      }
      
      if (file.size > 2 * 1024 * 1024) { // 2MB limit
        toast.error(`${file.name} is too large. Maximum size is 2MB`);
        return false;
      }
      
      return true;
    });

    if (validFiles.length > 0) {
      setUploadedFiles(validFiles);
      const file = validFiles[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        setScanInput({
          type: 'file',
          content: e.target?.result as string,
          filename: file.name
        });
      };
      reader.readAsText(file);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/plain': ['.py', '.js', '.php', '.java', '.cs', '.ts', '.jsx', '.tsx'],
      'application/x-python': ['.py'],
      'application/javascript': ['.js'],
      'application/x-php': ['.php'],
      'text/x-java-source': ['.java'],
      'text/x-csharp': ['.cs'],
      'application/typescript': ['.ts'],
      'text/jsx': ['.jsx'],
      'text/tsx': ['.tsx']
    },
    multiple: false,
    maxSize: 2 * 1024 * 1024 // 2MB
  });

  const handleInputChange = (value: string) => {
    setScanInput(prev => ({ ...prev, content: value }));
  };

  const handleTabChange = (tab: 'url' | 'file' | 'code') => {
    setActiveTab(tab);
    setScanInput(prev => ({ ...prev, type: tab }));
    setUploadedFiles([]);
  };

  const removeFile = () => {
    setUploadedFiles([]);
    setScanInput(prev => ({ ...prev, content: '', filename: '' }));
  };

  const handleScan = async () => {
    if (!scanInput.content.trim()) {
      toast.error('Please provide code to scan');
      return;
    }

    setIsScanning(true);
    
    try {
      // Prepare JSON payload for the appropriate API endpoint
      const payload: any = {};
      
      if (scanInput.type === 'url') {
        payload.url = scanInput.content;
      } else if (scanInput.type === 'file') {
        payload.code = scanInput.content;
      } else {
        payload.code = scanInput.content;
      }

      // Headers for API requests
      const headers: HeadersInit = {
        'Content-Type': 'application/json'
      };

      let results: any;
      if (analysisMode === 'static') {
        // Choose the appropriate API endpoint based on scanner type
        let endpoint: string;
        if (scannerType === 'sql') {
          endpoint = '/api/scan-sql-injection';
        } else if (scannerType === 'xss') {
          endpoint = '/api/scan-xss';
        } else if (scannerType === 'command') {
          endpoint = '/api/scan-command-injection';
        } else if (scannerType === 'csrf') {
          endpoint = '/api/scan-csrf';
        } else {
          throw new Error('Invalid scanner type');
        }
        const response = await fetch(`${config.API_BASE_URL}${endpoint}`, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || 'Scan failed');
        }
        results = await response.json();
      } else {
        // ML analysis
        const mlPayload: any = {
          type: scannerType,
          code: payload.code || payload.url,
          filename: scanInput.filename || (scannerType + '.py')
        };
        const response = await fetch(`${config.API_BASE_URL}/api/scan-ml`, {
          method: 'POST',
          headers,
          body: JSON.stringify(mlPayload)
        });
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || 'ML scan failed');
        }
        results = await response.json();
      }
      
      // Store results in localStorage for the Results page
      localStorage.setItem('scanResults', JSON.stringify({...results, scannerType, analysisMode}));
      localStorage.setItem('scanInput', JSON.stringify(scanInput));
      
      let vulnerabilityType: string;
      if (scannerType === 'sql') {
        vulnerabilityType = 'SQL injection vulnerabilities';
      } else if (scannerType === 'xss') {
        vulnerabilityType = 'XSS vulnerabilities';
      } else if (scannerType === 'command') {
        vulnerabilityType = 'Command injection vulnerabilities';
      } else if (scannerType === 'csrf') {
        vulnerabilityType = 'CSRF vulnerabilities';
      } else {
        vulnerabilityType = 'vulnerabilities';
      }
      if (analysisMode === 'static') {
        toast.success(`Scan completed! Found ${results.total_issues || 0} ${vulnerabilityType}`);
      } else {
        toast.success('ML analysis completed');
      }
      navigate('/results');
      
    } catch (error) {
      console.error('Scan error:', error);
      toast.error(error instanceof Error ? error.message : 'Scan failed. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const isValidUrl = (url: string) => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };

  const canScan = () => {
    if (isScanning) return false;
    
    switch (activeTab) {
      case 'url':
        return scanInput.content.trim() && isValidUrl(scanInput.content);
      case 'file':
        return uploadedFiles.length > 0 && scanInput.content.trim();
      case 'code':
        return scanInput.content.trim();
      default:
        return false;
    }
  };

  const getScannerTitle = () => {
    if (scannerType === 'sql') {
      return 'SQL Injection Vulnerability Scanner';
    } else if (scannerType === 'xss') {
      return 'Cross-Site Scripting (XSS) Scanner';
    } else if (scannerType === 'command') {
      return 'Command Injection Vulnerability Scanner';
    } else if (scannerType === 'csrf') {
      return 'CSRF (Cross-Site Request Forgery) Scanner';
    }
    return 'Security Scanner';
  };

  const getScannerDescription = () => {
    if (scannerType === 'sql') {
      return 'Upload your code, paste it directly, or scan GitHub files for SQL injection vulnerabilities';
    } else if (scannerType === 'xss') {
      return 'Upload your code, paste it directly, or scan GitHub files for XSS vulnerabilities';
    } else if (scannerType === 'command') {
      return 'Upload your code, paste it directly, or scan GitHub files for command injection vulnerabilities';
    } else if (scannerType === 'csrf') {
      return 'Upload your code, paste it directly, or scan GitHub files for CSRF vulnerabilities';
    }
    return 'Upload your code, paste it directly, or scan GitHub files for security vulnerabilities';
  };

  const getDetectionCapabilities = () => {
    if (scannerType === 'sql') {
      return [
        'String concatenation vulnerabilities',
        'Dynamic query construction',
        'Parameterized query validation',
        'NoSQL injection patterns',
        'Framework-specific vulnerabilities'
      ];
    } else if (scannerType === 'xss') {
      return [
        'Reflected XSS vulnerabilities',
        'Stored XSS patterns',
        'DOM-based XSS detection',
        'Template injection risks',
        'Unsafe HTML rendering'
      ];
    } else if (scannerType === 'command') {
      return [
        'os.system() vulnerabilities',
        'subprocess with shell=True',
        'Command string construction',
        'eval() and exec() misuse',
        'Dynamic module imports',
        'File operation injection'
      ];
    } else if (scannerType === 'csrf') {
      return [
        'Missing CSRF tokens in forms',
        'Flask routes without CSRF protection',
        'Django views with CSRF exemption',
        'AJAX requests without CSRF headers',
        'Cookie security misconfigurations',
        'Form validation bypasses'
      ];
    }
    return [];
  };

  // Show loading state while fetching configuration
  if (isLoadingConfig) {
    return (
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-lg shadow-lg p-8 text-center">
            <Loader2 className="h-12 w-12 animate-spin mx-auto mb-4 text-primary-600" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">Loading Scanner Configuration</h2>
            <p className="text-gray-600">Please wait while we load the available scanners...</p>
          </div>
        </div>
      </div>
    );
  }

  // Show message if no scanners are enabled
  if (!scannerConfig || !Object.values(scannerConfig.scanners).some(enabled => enabled === 1)) {
    return (
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-lg shadow-lg p-8 text-center">
            <AlertTriangle className="h-16 w-16 text-yellow-500 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">No Scanners Available</h2>
            <p className="text-gray-600 mb-4">
              All scanners are currently disabled. Please contact your administrator to enable scanners.
            </p>
            <button
              onClick={() => navigate('/home')}
              className="bg-primary-600 hover:bg-primary-700 text-white px-6 py-2 rounded-lg transition-colors"
            >
              Return to Home
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
            {getScannerTitle()}
          </h1>
          <p className="text-lg text-gray-600">
            {getScannerDescription()}
          </p>
        </div>

        {/* Scanner Type Selector */}
        <div className="bg-white rounded-lg shadow-lg mb-6 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Select Scanner Type</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {isScannerEnabled(scannerConfig, 'sql') && (
              <button
                onClick={() => setScannerType('sql')}
                className={`p-4 rounded-lg border-2 transition-all duration-200 ${
                  scannerType === 'sql'
                    ? 'border-primary-500 bg-primary-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center">
                  <Bug className={`h-6 w-6 mr-3 ${
                    scannerType === 'sql' ? 'text-primary-600' : 'text-gray-600'
                  }`} />
                  <div className="text-left">
                    <h4 className={`font-medium ${
                      scannerType === 'sql' ? 'text-primary-900' : 'text-gray-900'
                    }`}>
                      SQL Injection Scanner
                    </h4>
                    <p className={`text-sm ${
                      scannerType === 'sql' ? 'text-primary-600' : 'text-gray-600'
                    }`}>
                      Detect database injection vulnerabilities
                    </p>
                  </div>
                </div>
              </button>
            )}

            {isScannerEnabled(scannerConfig, 'xss') && (
              <button
                onClick={() => setScannerType('xss')}
                className={`p-4 rounded-lg border-2 transition-all duration-200 ${
                  scannerType === 'xss'
                    ? 'border-primary-500 bg-primary-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center">
                  <Shield className={`h-6 w-6 mr-3 ${
                    scannerType === 'xss' ? 'text-primary-600' : 'text-gray-600'
                  }`} />
                  <div className="text-left">
                    <h4 className={`font-medium ${
                      scannerType === 'xss' ? 'text-primary-900' : 'text-gray-900'
                    }`}>
                      XSS Scanner
                    </h4>
                    <p className={`text-sm ${
                      scannerType === 'xss' ? 'text-primary-600' : 'text-gray-600'
                    }`}>
                      Detect cross-site scripting vulnerabilities
                    </p>
                  </div>
                </div>
              </button>
            )}

            {isScannerEnabled(scannerConfig, 'command') && (
              <button
                onClick={() => setScannerType('command')}
                className={`p-4 rounded-lg border-2 transition-all duration-200 ${
                  scannerType === 'command'
                    ? 'border-primary-500 bg-primary-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center">
                  <AlertTriangle className={`h-6 w-6 mr-3 ${
                    scannerType === 'command' ? 'text-primary-600' : 'text-gray-600'
                  }`} />
                  <div className="text-left">
                    <h4 className={`font-medium ${
                      scannerType === 'command' ? 'text-primary-900' : 'text-gray-900'
                    }`}>
                      Command Injection Scanner
                    </h4>
                    <p className={`text-sm ${
                      scannerType === 'command' ? 'text-primary-600' : 'text-gray-600'
                    }`}>
                      Detect command injection vulnerabilities
                    </p>
                  </div>
                </div>
              </button>
            )}

            {isScannerEnabled(scannerConfig, 'csrf') && (
              <button
                onClick={() => setScannerType('csrf')}
                className={`p-4 rounded-lg border-2 transition-all duration-200 ${
                  scannerType === 'csrf'
                    ? 'border-primary-500 bg-primary-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center">
                  <Shield className={`h-6 w-6 mr-3 ${
                    scannerType === 'csrf' ? 'text-primary-600' : 'text-gray-600'
                  }`} />
                  <div className="text-left">
                    <h4 className={`font-medium ${
                      scannerType === 'csrf' ? 'text-primary-900' : 'text-gray-900'
                    }`}>
                      CSRF Scanner
                    </h4>
                    <p className={`text-sm ${
                      scannerType === 'csrf' ? 'text-primary-600' : 'text-gray-600'
                    }`}>
                      Detect cross-site request forgery vulnerabilities
                    </p>
                  </div>
                </div>
              </button>
            )}
          </div>
          {/* Analysis Mode Toggle */}
          <div className="mt-6">
            <h4 className="text-md font-medium text-gray-900 mb-2">Analysis Mode</h4>
            <div className="inline-flex rounded-md shadow-sm" role="group">
              <button
                type="button"
                onClick={() => setAnalysisMode('static')}
                className={`px-4 py-2 text-sm font-medium border ${analysisMode === 'static' ? 'bg-primary-600 text-white border-primary-600' : 'bg-white text-gray-700 border-gray-200 hover:bg-gray-50'}`}
              >
                Static Analysis
              </button>
              <button
                type="button"
                onClick={() => setAnalysisMode('ml')}
                className={`px-4 py-2 text-sm font-medium border -ml-px ${analysisMode === 'ml' ? 'bg-primary-600 text-white border-primary-600' : 'bg-white text-gray-700 border-gray-200 hover:bg-gray-50'}`}
              >
                ML Analysis
              </button>
            </div>
          </div>
        </div>

        {/* Main Scanner Interface */}
        <div className="bg-white rounded-lg shadow-lg overflow-hidden">
          {/* Tab Navigation */}
          <div className="flex border-b border-gray-200">
            <button
              onClick={() => handleTabChange('code')}
              className={`flex-1 py-4 px-6 text-center font-medium transition-colors duration-200 ${
                activeTab === 'code'
                  ? 'bg-primary-50 text-primary-600 border-b-2 border-primary-600'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              <Code className="h-5 w-5 mx-auto mb-1" />
              Paste Code
            </button>
            <button
              onClick={() => handleTabChange('file')}
              className={`flex-1 py-4 px-6 text-center font-medium transition-colors duration-200 ${
                activeTab === 'file'
                  ? 'bg-primary-50 text-primary-600 border-b-2 border-primary-600'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              <Upload className="h-5 w-5 mx-auto mb-1" />
              File Upload
            </button>
            <button
              onClick={() => handleTabChange('url')}
              className={`flex-1 py-4 px-6 text-center font-medium transition-colors duration-200 ${
                activeTab === 'url'
                  ? 'bg-primary-50 text-primary-600 border-b-2 border-primary-600'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              <LinkIcon className="h-5 w-5 mx-auto mb-1" />
              GitHub URL
            </button>
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {/* URL Tab */}
            {activeTab === 'url' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    GitHub Python File URL
                  </label>
                  <input
                    type="url"
                    value={scanInput.content}
                    onChange={(e) => handleInputChange(e.target.value)}
                    placeholder="https://github.com/user/repo/blob/main/file.py"
                    className="input-field"
                  />
                  <p className="text-sm text-gray-500 mt-1">
                    Enter a direct link to a Python file on GitHub
                  </p>
                </div>
              </div>
            )}

            {/* File Upload Tab */}
            {activeTab === 'file' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Upload Source Code File
                  </label>
                  
                  {uploadedFiles.length === 0 ? (
                    <div
                      {...getRootProps()}
                      className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors duration-200 ${
                        isDragActive
                          ? 'border-primary-400 bg-primary-50'
                          : 'border-gray-300 hover:border-gray-400'
                      }`}
                    >
                      <input {...getInputProps()} />
                      <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                      <p className="text-lg font-medium text-gray-700 mb-2">
                        {isDragActive
                          ? 'Drop your file here'
                          : 'Drag and drop your file here, or click to browse'}
                      </p>
                      <p className="text-sm text-gray-500">
                        Supports .py, .js, .php, .java, .cs, .ts files (max 2MB)
                      </p>
                    </div>
                  ) : (
                    <div className="border border-gray-300 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <FileText className="h-8 w-8 text-primary-600" />
                          <div>
                            <p className="font-medium text-gray-900">
                              {uploadedFiles[0].name}
                            </p>
                            <p className="text-sm text-gray-500">
                              {(uploadedFiles[0].size / 1024).toFixed(1)} KB
                            </p>
                          </div>
                        </div>
                        <button
                          onClick={removeFile}
                          className="text-gray-400 hover:text-gray-600"
                        >
                          <X className="h-5 w-5" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Code Paste Tab */}
            {activeTab === 'code' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Paste Source Code
                  </label>
                  <textarea
                    value={scanInput.content}
                    onChange={(e) => handleInputChange(e.target.value)}
                    placeholder={scannerType === 'sql' 
                      ? "# Paste your Python code here..." 
                      : scannerType === 'xss'
                      ? "# Paste your code here (Python, JavaScript, etc.)..."
                      : scannerType === 'command'
                      ? "# Paste your Python code here for command injection analysis..."
                      : "# Paste your code here (Python, HTML, JavaScript, etc.) for CSRF analysis..."
                    }
                    rows={12}
                    className="textarea-field font-mono text-sm"
                  />
                  <p className="text-sm text-gray-500 mt-1">
                    Paste your source code directly for analysis
                  </p>
                </div>
              </div>
            )}

            {/* Scan Button */}
            <div className="mt-6 pt-6 border-t border-gray-200">
              <button
                onClick={handleScan}
                disabled={!canScan()}
                className={`w-full py-3 px-4 rounded-lg font-medium transition-colors duration-200 flex items-center justify-center ${
                  canScan()
                    ? 'bg-primary-600 hover:bg-primary-700 text-white'
                    : 'bg-gray-200 text-gray-500 cursor-not-allowed'
                }`}
              >
                {isScanning ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin mr-2" />
                    Scanning Code...
                  </>
                ) : (
                  <>
                    {scannerType === 'sql' ? (
                      <Bug className="h-5 w-5 mr-2" />
                    ) : scannerType === 'xss' ? (
                      <Shield className="h-5 w-5 mr-2" />
                    ) : scannerType === 'command' ? (
                      <AlertTriangle className="h-5 w-5 mr-2" />
                    ) : (
                      <Shield className="h-5 w-5 mr-2" />
                    )}
                    Start {scannerType === 'sql' ? 'SQL Injection' : 
                      scannerType === 'xss' ? 'XSS' : 
                      scannerType === 'command' ? 'Command Injection' : 'CSRF'} Scan
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Information Cards */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">
              Supported Languages
            </h3>
            <ul className="space-y-2 text-sm text-gray-600">
              <li className="flex items-center">
                <CheckCircle className="h-4 w-4 text-green-500 mr-2" />
                Python (.py)
              </li>
              {scannerType === 'xss' && (
                <>
                  {/* <li className="flex items-center">
                    <CheckCircle className="h-4 w-4 text-green-500 mr-2" />
                    JavaScript (.js, .jsx, .ts, .tsx)
                  </li> */}
                </>
              )}
            </ul>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">
              Detection Capabilities
            </h3>
            <ul className="space-y-2 text-sm text-gray-600">
              {getDetectionCapabilities().map((capability, index) => (
                <li key={index} className="flex items-center">
                  <AlertTriangle className="h-4 w-4 text-yellow-500 mr-2" />
                  {capability}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Scanner; 
import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { 
  Upload, 
  Link as LinkIcon, 
  Code, 
  X,
  Loader2,
  FileText
} from 'lucide-react';
import toast from 'react-hot-toast';
import config from '../config.js';

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ScanInput {
  type: 'url' | 'file' | 'code';
  content: string;
  filename?: string;
}

const ScanModal: React.FC<ScanModalProps> = ({ isOpen, onClose }) => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'url' | 'file' | 'code'>('code');
  const [isScanning, setIsScanning] = useState(false);
  const [scanInput, setScanInput] = useState<ScanInput>({
    type: 'code',
    content: '',
    filename: ''
  });
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);

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
      const formData = new FormData();
      
      if (scanInput.type === 'url') {
        formData.append('url', scanInput.content);
      } else if (scanInput.type === 'file') {
        formData.append('code', scanInput.content);
      } else {
        formData.append('code', scanInput.content);
      }

      const headers: HeadersInit = {};

      const response = await fetch(`${config.API_BASE_URL}/api/scan`, {
        method: 'POST',
        headers,
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Scan failed');
      }

      const results = await response.json();
      
      // Store results in localStorage for the Results page
      localStorage.setItem('scanResults', JSON.stringify(results));
      localStorage.setItem('scanInput', JSON.stringify(scanInput));
      
      toast.success('Scan completed successfully');
      onClose();
      navigate('/results');
      
    } catch (error) {
      console.error('Scan error:', error);
      toast.error('Scan failed. Please try again.');
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

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-900">
            Start SQL Injection Scan
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors duration-200"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Content */}
        <div className="overflow-y-auto max-h-[calc(90vh-200px)]">
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
              Upload File
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
            {activeTab === 'url' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    GitHub File URL
                  </label>
                  <input
                    type="url"
                    value={scanInput.content}
                    onChange={(e) => handleInputChange(e.target.value)}
                    placeholder="https://github.com/username/repo/blob/main/file.py"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                    autoFocus
                  />
                  <p className="mt-1 text-sm text-gray-500">
                    Paste a GitHub URL to a Python, JavaScript, PHP, Java, or C# file
                  </p>
                </div>
              </div>
            )}

            {activeTab === 'file' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Upload Source Code File
                  </label>
                  <div
                    {...getRootProps()}
                    className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors duration-200 ${
                      isDragActive
                        ? 'border-primary-500 bg-primary-50'
                        : 'border-gray-300 hover:border-gray-400'
                    }`}
                  >
                    <input {...getInputProps()} />
                    <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                    <p className="text-sm text-gray-600">
                      Drop your file here, or click to browse
                    </p>
                    <p className="text-xs text-gray-500 mt-2">
                      Supports: .py, .js, .php, .java, .cs, .ts, .jsx, .tsx (Max 2MB)
                    </p>
                  </div>
                  
                  {uploadedFiles.length > 0 && (
                    <div className="mt-4">
                      <div className="flex items-center justify-between bg-gray-50 p-3 rounded-lg">
                        <div className="flex items-center space-x-2">
                          <FileText className="h-5 w-5 text-gray-600" />
                          <span className="text-sm font-medium text-gray-900">
                            {uploadedFiles[0].name}
                          </span>
                        </div>
                        <button
                          onClick={removeFile}
                          className="text-red-500 hover:text-red-700 transition-colors duration-200"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'code' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Paste Your Code
                  </label>
                  <textarea
                    value={scanInput.content}
                    onChange={(e) => handleInputChange(e.target.value)}
                    placeholder="# Paste your Python, JavaScript, PHP, Java, or C# code here..."
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent font-mono text-sm"
                    rows={12}
                    autoFocus
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 transition-colors duration-200"
          >
            Cancel
          </button>
          <button
            onClick={handleScan}
            disabled={!canScan()}
            className={`px-6 py-2 rounded-md font-medium transition-colors duration-200 flex items-center space-x-2 ${
              canScan()
                ? 'bg-primary-600 text-white hover:bg-primary-700'
                : 'bg-gray-300 text-gray-500 cursor-not-allowed'
            }`}
          >
            {isScanning ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <FileText className="h-4 w-4" />
            )}
            <span>{isScanning ? 'Scanning...' : 'Start Scan'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanModal; 
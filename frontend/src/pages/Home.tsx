import React from 'react';
import { Link } from 'react-router-dom';
// import { useAuth } from '../contexts/AuthContext';
// import ScanModal from '../components/ScanModal';
import { 
  Shield, 
  Search, 
  AlertTriangle, 
  CheckCircle, 
  Code, 
  Database, 
  FileText, 
  Zap,
  ArrowRight
} from 'lucide-react';

const Home: React.FC = () => {
  // const { isAuthenticated } = useAuth();
  // const [isScanModalOpen, setIsScanModalOpen] = useState(false);

  // const handleStartScanning = () => {
  //   // if (isAuthenticated) {
  //     setIsScanModalOpen(true);
  //   // } else {
  //   //   // If not authenticated, redirect to login with scanner redirect
  //   //   window.location.href = '/login?redirect=/scanner';
  //   // }
  // };
  
  const features = [
    {
      icon: <Search className="h-8 w-8 text-primary-600" />,
      title: "Advanced Detection",
      description: "Uses AST-based analysis to detect SQL injection vulnerabilities with high accuracy and low false positives."
    },
    {
      icon: <Code className="h-8 w-8 text-primary-600" />,
      title: "Multi-Language Support",
      description: "Supports Python, JavaScript, PHP, Java, and C# with framework-specific vulnerability patterns."
    },
    {
      icon: <Database className="h-8 w-8 text-primary-600" />,
      title: "Database Coverage",
      description: "Detects vulnerabilities across SQLite, MySQL, PostgreSQL, MongoDB, and other database systems."
    },
    {
      icon: <FileText className="h-8 w-8 text-primary-600" />,
      title: "Detailed Reports",
      description: "Generates comprehensive vulnerability reports with remediation suggestions and confidence scores."
    },
    {
      icon: <Zap className="h-8 w-8 text-primary-600" />,
      title: "Real-time Scanning",
      description: "Instant code analysis with support for GitHub URLs, file uploads, and direct code input."
    },
    {
      icon: <CheckCircle className="h-8 w-8 text-primary-600" />,
      title: "Security Best Practices",
      description: "Provides actionable remediation advice following industry security standards and best practices."
    }
  ];

  const stats = [
    { label: "Vulnerability Types", value: "15+" },
    { label: "Programming Languages", value: "5+" },
    { label: "Database Systems", value: "10+" },
    { label: "Detection Accuracy", value: "95%" }
  ];

  return (
    <div className="bg-gray-50 min-h-screen">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-primary-600 to-primary-800 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="flex justify-center mb-8">
              <div className="relative">
                <Shield className="h-24 w-24 text-primary-200" />
                <div className="absolute -top-2 -right-2 bg-danger-500 rounded-full p-2">
                  <AlertTriangle className="h-6 w-6 text-white animate-pulse" />
                </div>
              </div>
            </div>
            
            <h1 className="text-4xl md:text-6xl font-bold mb-6 animate-fade-in">
              Vulnerability Scanner
            </h1>
            
            <p className="text-xl md:text-2xl mb-8 text-primary-100 max-w-3xl mx-auto animate-fade-in">
              Advanced vulnerability detection tool for secure code development. 
              Identify and fix vulnerabilities before they become security risks.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center animate-slide-up">
              {/* <button
                onClick={handleStartScanning}
                className="bg-white text-primary-600 px-8 py-3 rounded-lg font-semibold hover:bg-gray-100 transition-colors duration-200 flex items-center justify-center"
              >
                Start Scanning
                <ArrowRight className="ml-2 h-5 w-5" />
              </button> */}
              
              <Link
                to="/about"
                className="border-2 border-white text-white px-8 py-3 rounded-lg font-semibold hover:bg-white hover:text-primary-600 transition-colors duration-200"
              >
                Learn More
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-12 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
            {stats.map((stat, index) => (
              <div key={index} className="p-6">
                <div className="text-3xl font-bold text-primary-600 mb-2">
                  {stat.value}
                </div>
                <div className="text-gray-600 text-sm">
                  {stat.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-6">
              Comprehensive Security Analysis
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Our advanced scanning engine combines multiple detection techniques to identify 
              vulnerabilities with precision and provide actionable remediation guidance.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <div 
                key={index} 
                className="bg-white p-6 rounded-lg shadow-lg hover:shadow-xl transition-shadow duration-300 animate-fade-in"
                style={{ animationDelay: `${index * 100}ms` }}
              >
                <div className="flex items-center mb-4">
                  {feature.icon}
                  <h3 className="text-xl font-semibold text-gray-900 ml-3">
                    {feature.title}
                  </h3>
                </div>
                <p className="text-gray-600 leading-relaxed">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="py-20 bg-primary-600 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            Ready to Secure Your Code?
          </h2>
          <p className="text-xl text-primary-100 mb-8 max-w-2xl mx-auto">
            Start scanning your applications for SQL injection vulnerabilities today. 
            Upload your code or paste it directly for instant analysis.
          </p>
          
          {/* <button
            onClick={handleStartScanning}
            className="bg-white text-primary-600 px-8 py-4 rounded-lg font-semibold hover:bg-gray-100 transition-colors duration-200 inline-flex items-center"
          >
            Start Scanning Now
            <ArrowRight className="ml-2 h-5 w-5" />
          </button> */}
        </div>
      </section>

      {/* Warning Section */}
      <section className="py-8 bg-warning-50 border-t border-warning-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-center text-warning-800">
            <AlertTriangle className="h-6 w-6 mr-3" />
            <p className="text-sm font-medium">
              <strong>Educational Use Only:</strong> This tool is designed for security research, 
              education, and authorized penetration testing. Do not use on systems without proper authorization.
            </p>
          </div>
        </div>
      </section>

      {/* Scan Modal - Commented out */}
      {/* <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
      /> */}
    </div>
  );
};

export default Home; 
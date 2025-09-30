import React from 'react';
import { Link } from 'react-router-dom';
import { 
  Shield, 
  AlertTriangle, 
  Code, 
  Database, 
  CheckCircle, 
  Info,
  ArrowRight,
  FileText,
  Users,
  Target,
  Zap
} from 'lucide-react';

const About: React.FC = () => {
  const features = [
    {
      icon: <Code className="h-6 w-6 text-primary-600" />,
      title: "AST-Based Analysis",
      description: "Uses Abstract Syntax Tree analysis for accurate vulnerability detection with minimal false positives."
    },
    {
      icon: <Database className="h-6 w-6 text-primary-600" />,
      title: "Multi-Database Support",
      description: "Detects vulnerabilities across SQLite, MySQL, PostgreSQL, MongoDB, and other database systems."
    },
    {
      icon: <Zap className="h-6 w-6 text-primary-600" />,
      title: "Real-time Scanning",
      description: "Instant analysis with support for GitHub URLs, file uploads, and direct code input."
    },
    {
      icon: <FileText className="h-6 w-6 text-primary-600" />,
      title: "Detailed Reports",
      description: "Comprehensive vulnerability reports with code snippets, remediation suggestions, and confidence scores."
    }
  ];

  const vulnerabilityTypes = [
    "String Concatenation Vulnerabilities",
    "Dynamic Query Construction",
    "Unsafe Parameter Binding",
    "NoSQL Injection Patterns",
    "Framework-Specific Vulnerabilities",
    "Input Validation Bypass",
    "Authentication Bypass",
    "Data Extraction Exploits",
    "Boolean-Based Blind Injection",
    "Time-Based Blind Injection",
    "Union-Based Injection",
    "Error-Based Injection",
    "Second-Order SQL Injection",
    "Stored Procedure Injection",
    "Header-Based Injection"
  ];

  const bestPractices = [
    {
      title: "Use Parameterized Queries",
      description: "Always use parameterized queries or prepared statements to separate SQL logic from user input.",
      example: "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    },
    {
      title: "Input Validation",
      description: "Validate and sanitize all user inputs before processing them in database queries.",
      example: "user_id = int(request.form['user_id']) if request.form['user_id'].isdigit() else None"
    },
    {
      title: "Principle of Least Privilege",
      description: "Use database accounts with minimal necessary permissions for application operations.",
      example: "Create dedicated database users with only SELECT, INSERT, UPDATE permissions as needed."
    },
    {
      title: "Error Handling",
      description: "Implement proper error handling that doesn't reveal sensitive database information.",
      example: "Log detailed errors internally while showing generic error messages to users."
    }
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-primary-600 to-primary-800 text-white py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <Shield className="h-16 w-16 text-primary-200 mx-auto mb-6" />
            <h1 className="text-4xl md:text-5xl font-bold mb-6">
              About SQL Injection Scanner
            </h1>
            <p className="text-xl text-primary-100 max-w-3xl mx-auto">
              Advanced security analysis tool designed to identify and prevent SQL injection vulnerabilities 
              in your applications before they become security risks.
            </p>
          </div>
        </div>
      </section>

      {/* Overview Section */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl font-bold text-gray-900 mb-6">
                Comprehensive Security Analysis
              </h2>
              <p className="text-lg text-gray-600 mb-6">
                Our SQL injection scanner utilizes advanced static analysis techniques to identify potential 
                vulnerabilities in your code. By analyzing the Abstract Syntax Tree (AST) of your source code, 
                it can detect complex vulnerability patterns that traditional regex-based scanners might miss.
              </p>
              <p className="text-lg text-gray-600 mb-8">
                The tool supports multiple programming languages and frameworks, providing detailed reports 
                with remediation suggestions to help you secure your applications effectively.
              </p>
              <Link
                to="/scanner"
                className="btn-primary inline-flex items-center"
              >
                Try Scanner Now
                <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </div>
            <div className="grid grid-cols-2 gap-6">
              {features.map((feature, index) => (
                <div key={index} className="bg-gray-50 p-6 rounded-lg">
                  <div className="flex items-center mb-3">
                    {feature.icon}
                    <h3 className="text-lg font-semibold text-gray-900 ml-3">
                      {feature.title}
                    </h3>
                  </div>
                  <p className="text-gray-600 text-sm">
                    {feature.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Vulnerability Types Section */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-900 mb-6">
              Vulnerability Detection Coverage
            </h2>
            <p className="text-lg text-gray-600 max-w-3xl mx-auto">
              Our scanner identifies a comprehensive range of SQL injection vulnerability types, 
              from basic string concatenation to advanced blind injection techniques.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {vulnerabilityTypes.map((type, index) => (
              <div key={index} className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
                <div className="flex items-center">
                  <AlertTriangle className="h-5 w-5 text-warning-600 mr-3" />
                  <span className="text-sm font-medium text-gray-900">
                    {type}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Best Practices Section */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-900 mb-6">
              Security Best Practices
            </h2>
            <p className="text-lg text-gray-600 max-w-3xl mx-auto">
              Follow these essential security practices to protect your applications from SQL injection attacks.
            </p>
          </div>
          
          <div className="space-y-8">
            {bestPractices.map((practice, index) => (
              <div key={index} className="bg-gray-50 rounded-lg p-8">
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    <CheckCircle className="h-8 w-8 text-success-600" />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-xl font-semibold text-gray-900 mb-2">
                      {practice.title}
                    </h3>
                    <p className="text-gray-600 mb-4">
                      {practice.description}
                    </p>
                    <div className="bg-gray-900 text-gray-100 p-3 rounded-lg font-mono text-sm">
                      {practice.example}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Technical Details Section */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            <div>
              <h2 className="text-3xl font-bold text-gray-900 mb-6">
                How It Works
              </h2>
              <div className="space-y-6">
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm font-bold">
                      1
                    </div>
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-2">
                      Code Analysis
                    </h3>
                    <p className="text-gray-600">
                      The scanner parses your source code into an Abstract Syntax Tree (AST) 
                      to understand the code structure and identify potential data flow paths.
                    </p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm font-bold">
                      2
                    </div>
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-2">
                      Pattern Detection
                    </h3>
                    <p className="text-gray-600">
                      Advanced pattern matching algorithms identify vulnerable code patterns, 
                      including string concatenation, unsafe parameter binding, and dynamic query construction.
                    </p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm font-bold">
                      3
                    </div>
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-2">
                      Risk Assessment
                    </h3>
                    <p className="text-gray-600">
                      Each potential vulnerability is assessed for severity and confidence level, 
                      with detailed remediation suggestions provided for each finding.
                    </p>
                  </div>
                </div>
              </div>
            </div>
            
            <div>
              <h2 className="text-3xl font-bold text-gray-900 mb-6">
                Supported Technologies
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                <div className="bg-white p-6 rounded-lg shadow-sm">
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">
                    Languages
                  </h3>
                  <ul className="space-y-2 text-gray-600">
                    <li>• Python</li>
                    <li>• JavaScript/TypeScript</li>
                    <li>• PHP</li>
                    <li>• Java</li>
                    <li>• C#</li>
                  </ul>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm">
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">
                    Frameworks
                  </h3>
                  <ul className="space-y-2 text-gray-600">
                    <li>• Flask/Django</li>
                    <li>• Express.js</li>
                    <li>• Spring Boot</li>
                    <li>• ASP.NET</li>
                    <li>• Laravel</li>
                  </ul>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm">
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">
                    Databases
                  </h3>
                  <ul className="space-y-2 text-gray-600">
                    <li>• SQLite</li>
                    <li>• MySQL</li>
                    <li>• PostgreSQL</li>
                    <li>• MongoDB</li>
                    <li>• SQL Server</li>
                  </ul>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm">
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">
                    Libraries
                  </h3>
                  <ul className="space-y-2 text-gray-600">
                    <li>• SQLAlchemy</li>
                    <li>• Mongoose</li>
                    <li>• Sequelize</li>
                    <li>• Entity Framework</li>
                    <li>• Hibernate</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Educational Warning */}
      <section className="py-12 bg-warning-50 border-t border-warning-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="flex items-center justify-center mb-4">
              <AlertTriangle className="h-8 w-8 text-warning-600 mr-3" />
              <h2 className="text-2xl font-bold text-warning-900">
                Important Security Notice
              </h2>
            </div>
            <p className="text-lg text-warning-800 max-w-3xl mx-auto">
              This tool is designed for educational purposes, security research, and authorized penetration testing only. 
              Always ensure you have proper authorization before testing any system or application. 
              The developers are not responsible for any misuse of this tool.
            </p>
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="py-16 bg-primary-600 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-bold mb-6">
            Ready to Secure Your Code?
          </h2>
          <p className="text-xl text-primary-100 mb-8 max-w-2xl mx-auto">
            Start scanning your applications for SQL injection vulnerabilities today.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/scanner"
              className="bg-white text-primary-600 px-8 py-3 rounded-lg font-semibold hover:bg-gray-100 transition-colors duration-200 inline-flex items-center justify-center"
            >
              Start Scanning
              <ArrowRight className="ml-2 h-5 w-5" />
            </Link>
            
            <Link
              to="/"
              className="border-2 border-white text-white px-8 py-3 rounded-lg font-semibold hover:bg-white hover:text-primary-600 transition-colors duration-200 inline-flex items-center justify-center"
            >
              Learn More
              <Info className="ml-2 h-5 w-5" />
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
};

export default About; 
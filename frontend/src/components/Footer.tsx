import React from 'react';
import { Shield, Github, Mail } from 'lucide-react';

const Footer: React.FC = () => {
  return (
    <footer className="bg-gray-900 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Brand Section */}
          <div className="flex flex-col items-center md:items-start">
            <div className="flex items-center space-x-2 mb-4">
              <Shield className="h-8 w-8 text-primary-400" />
              <span className="text-xl font-bold">SQL Injection Scanner</span>
            </div>
            <p className="text-gray-400 text-sm text-center md:text-left">
              Advanced SQL injection vulnerability detection and analysis tool
              for secure code development.
            </p>
          </div>

          {/* Links Section */}
          <div className="flex flex-col items-center md:items-start">
            <h3 className="text-lg font-semibold mb-4">Resources</h3>
            <ul className="space-y-2 text-sm text-gray-400">
              <li>
                <a 
                  href="#" 
                  className="hover:text-primary-400 transition-colors duration-200"
                >
                  Documentation
                </a>
              </li>
              <li>
                <a 
                  href="#" 
                  className="hover:text-primary-400 transition-colors duration-200"
                >
                  Security Best Practices
                </a>
              </li>
              <li>
                <a 
                  href="#" 
                  className="hover:text-primary-400 transition-colors duration-200"
                >
                  Vulnerability Database
                </a>
              </li>
              <li>
                <a 
                  href="#" 
                  className="hover:text-primary-400 transition-colors duration-200"
                >
                  API Reference
                </a>
              </li>
            </ul>
          </div>

          {/* Contact Section */}
          <div className="flex flex-col items-center md:items-start">
            <h3 className="text-lg font-semibold mb-4">Connect</h3>
            <div className="flex space-x-4">
              <a 
                href="#" 
                className="text-gray-400 hover:text-primary-400 transition-colors duration-200"
                aria-label="GitHub"
              >
                <Github className="h-6 w-6" />
              </a>
              <a 
                href="#" 
                className="text-gray-400 hover:text-primary-400 transition-colors duration-200"
                aria-label="Email"
              >
                <Mail className="h-6 w-6" />
              </a>
            </div>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="border-t border-gray-800 mt-8 pt-8 text-center">
          <p className="text-gray-400 text-sm">
            &copy; {new Date().getFullYear()} SQL Injection Scanner. Built for security research and education.
          </p>
          <p className="text-gray-500 text-xs mt-2">
            ⚠️ This tool is designed for educational purposes and authorized security testing only.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer; 
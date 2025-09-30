import config from '../config.js';

export interface ScannerConfig {
  scanners: {
    sql_injection: number;
    xss: number;
    command_injection: number;
    csrf: number;
  };
  description: string;
}

export const fetchScannerConfig = async (): Promise<ScannerConfig> => {
  try {
    const response = await fetch(`${config.API_BASE_URL}/api/scanner-config`);
    if (!response.ok) {
      throw new Error('Failed to fetch scanner configuration');
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching scanner config:', error);
    // Return default config if fetch fails
    return {
      scanners: {
        sql_injection: 1,
        xss: 1,
        command_injection: 1,
        csrf: 1
      },
      description: 'Default configuration'
    };
  }
};

export const isScannerEnabled = (config: ScannerConfig, scannerType: string): boolean => {
  const scannerKey = scannerType === 'sql' ? 'sql_injection' : 
                    scannerType === 'xss' ? 'xss' : 
                    scannerType === 'command' ? 'command_injection' : 
                    scannerType === 'csrf' ? 'csrf' : '';
  
  return config.scanners[scannerKey as keyof typeof config.scanners] === 1;
}; 
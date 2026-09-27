import React, { useState } from 'react';
import { phpFileTemplates } from '../data/phpFiles';
import { AppConfig, PhpFileTemplate } from '../types';
import { Copy, Check, Download, FileCode, Search, ShieldCheck, Database, Terminal, FileText, Settings } from 'lucide-react';

interface FileExplorerProps {
  config: AppConfig;
}

export const FileExplorer: React.FC<FileExplorerProps> = ({ config }) => {
  const [selectedFile, setSelectedFile] = useState<PhpFileTemplate>(phpFileTemplates[0]);
  const [copied, setCopied] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');

  const currentContent = selectedFile.generateContent(config);

  const handleCopy = () => {
    navigator.clipboard.writeText(currentContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadSingle = () => {
    const blob = new Blob([currentContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = selectedFile.name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const filteredFiles = phpFileTemplates.filter(
    (f) =>
      f.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.description.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.category.toLowerCase().includes(searchFilter.toLowerCase())
  );

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'auth':
        return <ShieldCheck className="w-4 h-4 text-emerald-500" />;
      case 'core':
        return <Database className="w-4 h-4 text-blue-500" />;
      case 'sync':
        return <Terminal className="w-4 h-4 text-purple-500" />;
      case 'config':
        return <Settings className="w-4 h-4 text-amber-500" />;
      case 'debian':
        return <Terminal className="w-4 h-4 text-rose-500" />;
      default:
        return <FileCode className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 transition-colors duration-200">
      {/* Overview header */}
      <div className="mb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Debian PHP Application Source Files</h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Complete, self-contained files ready to deploy to <code>/var/www/eop-antispam</code> on Debian 11/12.
          </p>
        </div>
        <div className="flex items-center space-x-3 text-xs flex-wrap gap-2">
          <span className="bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 font-medium">
            {phpFileTemplates.length} Production Files
          </span>
          <span className="bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 px-3 py-1.5 rounded-lg border border-emerald-200 dark:border-emerald-800 font-medium">
            Active Directory LDAP Group Validated
          </span>
          <span className="bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300 px-3 py-1.5 rounded-lg border border-blue-200 dark:border-blue-800 font-medium">
            4 Individual MariaDB Tables
          </span>
        </div>
      </div>

      {/* Main split explorer */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden grid grid-cols-1 lg:grid-cols-12 min-h-[700px] transition-colors duration-200">
        {/* Left Sidebar: File Tree */}
        <div className="lg:col-span-4 border-r border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/60 flex flex-col">
          {/* File search */}
          <div className="p-3.5 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400 dark:text-slate-500" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Search PHP files, SQL, scripts..."
                className="w-full text-xs pl-9 pr-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 text-slate-800 dark:text-slate-100 placeholder-slate-400"
              />
            </div>
          </div>

          {/* File listing */}
          <div className="overflow-y-auto grow p-2 space-y-1">
            {filteredFiles.map((file) => {
              const isSelected = selectedFile.name === file.name;
              return (
                <button
                  key={file.name}
                  onClick={() => setSelectedFile(file)}
                  className={`w-full text-left px-3 py-2.5 rounded-xl transition flex items-start space-x-3 ${
                    isSelected
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'hover:bg-slate-100 dark:hover:bg-slate-800/70 text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <div className="mt-0.5">{getCategoryIcon(file.category)}</div>
                  <div className="overflow-hidden grow">
                    <div className="flex items-center justify-between">
                      <span className={`font-mono text-xs font-semibold truncate ${isSelected ? 'text-white' : 'text-slate-900 dark:text-slate-100'}`}>
                        {file.name}
                      </span>
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                          isSelected ? 'bg-blue-700 text-blue-100' : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        {file.category}
                      </span>
                    </div>
                    <p className={`text-[11px] truncate mt-0.5 ${isSelected ? 'text-blue-100' : 'text-slate-500 dark:text-slate-400'}`}>
                      {file.description}
                    </p>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Quick info footer */}
          <div className="p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80 text-[11px] text-slate-500 dark:text-slate-400 space-y-1">
            <div className="flex justify-between">
              <span>Target OS:</span>
              <span className="font-semibold text-slate-700 dark:text-slate-300">Debian 11 / 12 Linux</span>
            </div>
            <div className="flex justify-between">
              <span>DB Server:</span>
              <span className="font-mono text-blue-600 dark:text-blue-400">{config.dbHost}:{config.dbPort}</span>
            </div>
            <div className="flex justify-between">
              <span>LDAP Port:</span>
              <span className="font-mono text-slate-700 dark:text-slate-300">{config.ldapPort} ({config.ldapUseSsl ? 'LDAPS' : 'LDAP - No SSL Req'})</span>
            </div>
          </div>
        </div>

        {/* Right Pane: Code Viewer */}
        <div className="lg:col-span-8 flex flex-col bg-slate-950 text-slate-100">
          {/* File details bar */}
          <div className="p-4 bg-slate-900 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center space-x-2">
              <FileText className="w-4 h-4 text-blue-400" />
              <div>
                <span className="font-mono text-sm font-bold text-white">{selectedFile.path}</span>
                <span className="text-xs text-slate-400 ml-2">({currentContent.split('\n').length} lines)</span>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={handleCopy}
                className="flex items-center space-x-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium transition border border-slate-700"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy File</span>
                  </>
                )}
              </button>

              <button
                onClick={handleDownloadSingle}
                className="flex items-center space-x-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded-lg text-xs font-semibold transition shadow-sm"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download</span>
              </button>
            </div>
          </div>

          {/* Description banner */}
          <div className="px-4 py-2.5 bg-slate-900/60 border-b border-slate-800/80 text-xs text-slate-300 flex items-center justify-between">
            <span>{selectedFile.description}</span>
            <span className="text-[10px] text-slate-500 font-mono">UTF-8 CRLF/LF safe</span>
          </div>

          {/* Source Code Content */}
          <div className="p-4 overflow-x-auto grow font-mono text-xs leading-relaxed max-h-[640px] select-text">
            <pre className="text-slate-200">
              <code>{currentContent}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};

import React from 'react';
import { Shield, Code, Settings, Server, Play, Download, Moon, Sun, Key, Lock, Sparkles, CloudUpload } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export type ActiveTab = 'simulator' | 'config_page' | 'wizard' | 'files' | 'config' | 'guide';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  onDownloadZip: () => void;
  isDownloading: boolean;
  isSetupLocked?: boolean;
  onPushToEop?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  onDownloadZip,
  isDownloading,
  isSetupLocked = false,
  onPushToEop,
}) => {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="bg-white dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 text-slate-800 dark:text-white sticky top-0 z-40 shadow-xs dark:shadow-md transition-colors duration-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-md shadow-blue-600/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-base text-slate-900 dark:text-white tracking-tight">EOP Anti-Spam Manager</span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Exchange Online Protection Policy Administration
              </p>
            </div>
          </div>

          {/* Navigation Items */}
          <nav className="hidden md:flex items-center space-x-1">
            <button
              onClick={() => setActiveTab('simulator')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'simulator'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/80'
              }`}
            >
              <Play className="w-3.5 h-3.5" />
              <span>Live App Simulator</span>
            </button>

            {/* Direct Configuration Page Link */}
            <button
              onClick={() => setActiveTab('config_page')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'config_page'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-indigo-700 dark:text-indigo-300 bg-indigo-50/70 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800/60 hover:bg-indigo-100 dark:hover:bg-indigo-900/60'
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              <span>Configuration Page</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold ${
                activeTab === 'config_page'
                  ? 'bg-indigo-700 text-indigo-100'
                  : 'bg-indigo-200/80 dark:bg-indigo-900/70 text-indigo-800 dark:text-indigo-200'
              }`}>
                Keys & LDAP
              </span>
            </button>

            {/* Initial Setup Wizard Button */}
            <button
              onClick={() => setActiveTab('wizard')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'wizard'
                  ? 'bg-amber-600 text-white shadow-sm'
                  : 'text-amber-800 dark:text-amber-300 bg-amber-50/70 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 hover:bg-amber-100 dark:hover:bg-amber-900/60'
              }`}
            >
              {isSetupLocked ? <Lock className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" /> : <Sparkles className="w-3.5 h-3.5 text-amber-500" />}
              <span>Setup Wizard</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold ${
                isSetupLocked
                  ? 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
                  : 'bg-amber-200/80 dark:bg-amber-900/70 text-amber-900 dark:text-amber-100'
              }`}>
                {isSetupLocked ? 'Locked' : 'Wizard'}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('files')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'files'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/80'
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              <span>PHP Files & Code</span>
            </button>

            <button
              onClick={() => setActiveTab('config')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'config'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/80'
              }`}
            >
              <Settings className="w-3.5 h-3.5" />
              <span>Setup Parameters</span>
            </button>

            <button
              onClick={() => setActiveTab('guide')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'guide'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/80'
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              <span>Debian Setup Guide</span>
            </button>
          </nav>

          {/* Action buttons: Push to EOP + Dark Mode Toggle + One-Click Download ZIP */}
          <div className="flex items-center space-x-2">
            {/* Push Changes to EOP Button */}
            {onPushToEop && (
              <button
                onClick={onPushToEop}
                className="flex items-center space-x-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white px-3.5 py-2 rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer"
                title="Push changes from MariaDB tables to Exchange Online Protection (EOP)"
              >
                <CloudUpload className="w-3.5 h-3.5" />
                <span>Push to EOP</span>
              </button>
            )}

            {/* Dark Mode Toggle */}
            <button
              onClick={toggleTheme}
              className="p-2 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white bg-slate-100 dark:bg-slate-800/80 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-700 transition flex items-center space-x-1.5 text-xs font-semibold cursor-pointer"
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            >
              {theme === 'dark' ? (
                <>
                  <Sun className="w-4 h-4 text-amber-400" />
                  <span className="hidden sm:inline text-slate-200">Light</span>
                </>
              ) : (
                <>
                  <Moon className="w-4 h-4 text-indigo-600" />
                  <span className="hidden sm:inline text-slate-700">Dark</span>
                </>
              )}
            </button>

            <button
              onClick={onDownloadZip}
              disabled={isDownloading}
              className="flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-500 text-white px-3.5 py-2 rounded-lg text-xs font-semibold shadow-xs transition disabled:opacity-50 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{isDownloading ? 'Building ZIP...' : 'Download Project (.zip)'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation bar */}
      <div className="md:hidden flex border-t border-slate-200 dark:border-slate-800 bg-slate-50/95 dark:bg-slate-950/95 overflow-x-auto px-2 py-1.5 space-x-1 text-xs">
        {onPushToEop && (
          <button
            onClick={onPushToEop}
            className="px-3 py-1.5 rounded whitespace-nowrap font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 text-white flex items-center gap-1 shadow-xs cursor-pointer"
          >
            <CloudUpload className="w-3 h-3" />
            <span>Push to EOP</span>
          </button>
        )}
        <button
          onClick={() => setActiveTab('simulator')}
          className={`px-3 py-1.5 rounded whitespace-nowrap font-medium ${activeTab === 'simulator' ? 'bg-blue-600 text-white' : 'text-slate-600 dark:text-slate-400'}`}
        >
          Live Simulator
        </button>
        <button
          onClick={() => setActiveTab('config_page')}
          className={`px-3 py-1.5 rounded whitespace-nowrap font-semibold flex items-center gap-1 ${activeTab === 'config_page' ? 'bg-indigo-600 text-white' : 'text-indigo-700 dark:text-indigo-300 bg-indigo-50 dark:bg-indigo-950/50'}`}
        >
          <Key className="w-3 h-3" />
          <span>Config Page</span>
        </button>
        <button
          onClick={() => setActiveTab('wizard')}
          className={`px-3 py-1.5 rounded whitespace-nowrap font-semibold flex items-center gap-1 ${activeTab === 'wizard' ? 'bg-amber-600 text-white' : 'text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/50'}`}
        >
          {isSetupLocked ? <Lock className="w-3 h-3" /> : <Sparkles className="w-3 h-3 text-amber-500" />}
          <span>Setup Wizard {isSetupLocked ? '(Locked)' : ''}</span>
        </button>
        <button
          onClick={() => setActiveTab('files')}
          className={`px-3 py-1.5 rounded whitespace-nowrap font-medium ${activeTab === 'files' ? 'bg-blue-600 text-white' : 'text-slate-600 dark:text-slate-400'}`}
        >
          PHP Files
        </button>
        <button
          onClick={() => setActiveTab('config')}
          className={`px-3 py-1.5 rounded whitespace-nowrap font-medium ${activeTab === 'config' ? 'bg-blue-600 text-white' : 'text-slate-600 dark:text-slate-400'}`}
        >
          Parameters
        </button>
        <button
          onClick={() => setActiveTab('guide')}
          className={`px-3 py-1.5 rounded whitespace-nowrap font-medium ${activeTab === 'guide' ? 'bg-blue-600 text-white' : 'text-slate-600 dark:text-slate-400'}`}
        >
          Debian Guide
        </button>
      </div>
    </header>
  );
};

import React, { useState } from 'react';
import JSZip from 'jszip';
import { defaultAppConfig, phpFileTemplates } from './data/phpFiles';
import { AppConfig } from './types';
import { Navbar, ActiveTab } from './components/Navbar';
import { LiveSimulator } from './components/LiveSimulator';
import { FileExplorer } from './components/FileExplorer';
import { ConfigGenerator } from './components/ConfigGenerator';
import { DebianGuide } from './components/DebianGuide';
import { SetupWizard } from './components/SetupWizard';
import { ScreenshotsView } from './components/ScreenshotsView';
import { ThemeProvider } from './context/ThemeContext';

function AppContent() {
  const [config, setConfig] = useState<AppConfig>(defaultAppConfig);
  const [activeTab, setActiveTab] = useState<ActiveTab>('simulator');
  const [isDownloading, setIsDownloading] = useState(false);
  const [isSetupLocked, setIsSetupLocked] = useState<boolean>(() => {
    return localStorage.getItem('eop_setup_completed') === 'true';
  });
  const [pushTriggerCount, setPushTriggerCount] = useState<number>(0);
  const [pendingChangesCount, setPendingChangesCount] = useState<number>(4);

  const handlePushToEop = () => {
    setActiveTab('simulator');
    setPushTriggerCount((prev) => prev + 1);
  };

  // Generate and download full project ZIP archive
  const handleDownloadZip = async () => {
    try {
      setIsDownloading(true);
      const zip = new JSZip();
      const folder = zip.folder('eop-antispam-php-mariadb');

      if (folder) {
        phpFileTemplates.forEach((file) => {
          const content = file.generateContent(config);
          folder.file(file.path, content);
        });

        // Include actual PNG screenshots in zip archive
        const docsFolder = folder.folder('docs/screenshots');
        const screenshotFiles = [
          'dashboard-dark.png',
          'smart-sorter-modal.png',
          'setup-wizard.png',
          'push-summary-modal.png',
          'config-center.png',
        ];
        for (const sFile of screenshotFiles) {
          try {
            const res = await fetch(`/screenshots/${sFile}`);
            if (res.ok) {
              const blobData = await res.arrayBuffer();
              docsFolder?.file(sFile, blobData);
            }
          } catch {
            // Fallback gracefully
          }
        }

        const zipBlob = await zip.generateAsync({ type: 'blob' });
        const downloadUrl = URL.createObjectURL(zipBlob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = 'eop-antispam-php-mariadb.zip';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(downloadUrl);
      }
    } catch (error) {
      console.error('Error generating project zip:', error);
      alert('Could not generate ZIP archive. You can copy or download files individually in the File Explorer tab.');
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-950 text-slate-800 dark:text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white transition-colors duration-200">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onDownloadZip={handleDownloadZip}
        isDownloading={isDownloading}
        isSetupLocked={isSetupLocked}
        onPushToEop={handlePushToEop}
        pendingChangesCount={pendingChangesCount}
      />

      {/* Main Content Area */}
      <main className="grow">
        {activeTab === 'simulator' && (
          <LiveSimulator
            key="simulator"
            config={config}
            initialTab="allowed_senders"
            triggerPushActionCount={pushTriggerCount}
            onPendingChangesCountChange={setPendingChangesCount}
            onTabChange={(tab) => {
              if (tab === 'config_center' || tab === 'ldap_db') {
                setActiveTab('config_page');
              }
            }}
          />
        )}
        {activeTab === 'config_page' && (
          <LiveSimulator
            key="config_page"
            config={config}
            initialTab="config_center"
            triggerPushActionCount={pushTriggerCount}
            onPendingChangesCountChange={setPendingChangesCount}
            onLeaveConfigPage={() => setActiveTab('simulator')}
            onTabChange={(tab) => {
              if (tab !== 'config_center' && tab !== 'ldap_db') {
                setActiveTab('simulator');
              }
            }}
          />
        )}
        {activeTab === 'wizard' && (
          <SetupWizard
            config={config}
            setConfig={setConfig}
            isLocked={isSetupLocked}
            setIsLocked={setIsSetupLocked}
            onFinishSetup={() => setActiveTab('simulator')}
            onOpenConfigPage={() => setActiveTab('config_page')}
          />
        )}
        {activeTab === 'files' && <FileExplorer config={config} />}
        {activeTab === 'config' && (
          <ConfigGenerator
            config={config}
            setConfig={setConfig}
            onOpenConfigPage={() => setActiveTab('config_page')}
          />
        )}
        {activeTab === 'guide' && <DebianGuide config={config} />}
        {activeTab === 'screenshots' && <ScreenshotsView />}
      </main>

      {/* Global Application Footer */}
      <footer className="bg-slate-900 dark:bg-slate-950 border-t border-slate-800 text-slate-400 py-6 text-xs text-center transition-colors duration-200">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="font-semibold text-slate-200">Exchange Online Protection Anti-Spam Manager</span>
          </div>
          <div>
            Centralized Inbound Filter Policies, Allowed &amp; Blocked Lists
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
}


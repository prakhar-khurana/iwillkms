import React, { useState } from 'react';
import Header from './components/Header';
import FileInput from './components/FileInput';
import PolicyInput from './components/PolicyInput';
import Results from './components/Results';
import InfoPage from './components/InfoPage';
import ResultsChart from './components/ResultsChart';
import {AnalysisResult} from './components/ViolationCard';
import ViolationFrequencyChart from './components/ViolationFrequencyChart';
// Extend Violation for analysis results; status may be "OK", "NOT FOLLOWED" or "ERROR"

const App: React.FC = () => {
  const [fileContent, setFileContent] = useState<string>('');
  const [fileName, setFileName] = useState<string>('');
  const [policy, setPolicy] = useState<string>('');
  const [results, setResults] = useState<AnalysisResult[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [showInfo, setShowInfo] = useState<boolean>(false);

  /**
   * Callback invoked when a file is successfully read by the FileInput component.
   * @param content The raw text content of the file
   * @param name The name of the file
   */
  const handleFileLoaded = (content: string, name: string) => {
    setFileContent(content);
    setFileName(name);
    // Clear previous results when new file is selected
    setResults([]);
    setError('');
  };

  /**
   * Callback invoked when the policy textarea content changes.
   * @param value The updated JSON policy string
   */
  const handlePolicyChange = (value: string) => {
    setPolicy(value);
  };

  /**
   * Trigger analysis of the uploaded PLC source code by invoking the Wasm module.
   */
  const handleAnalyze = async () => {
    setError('');
    if (!fileContent) {
      setError('Please upload a source code file before analyzing.');
      return;
    }
    setLoading(true);
    try {
      /**
       * Dynamically import the wasm-bindgen generated module. The @vite-ignore
       * comment instructs Vite not to attempt to bundle or pre-bundle this import,
       * allowing it to remain as a runtime dynamic import. You must ensure
       * that the compiled files (plc_checker.js and plc_checker_bg.wasm) are
       * available in the `wasm` directory at the project root as described in
       * the project README.
       */
      const module = await import(/* @vite-ignore */ '../wasm/plc_secure_checker_lib.js');
      // If the module has a default export, call it to initialize the wasm module.
      if (typeof module.default === 'function') {
        await module.default();
      }
      // Retrieve the exported check_plc_code function from the wasm module.
      const checkPlcCode: (src: string, policy: string, fileName: string) => string =
        module.check_plc_code || module.checkPlcCode || module.check_plc_code;
      if (typeof checkPlcCode !== 'function') {
        throw new Error('WASM function check_plc_code was not found. Make sure the Rust code is compiled with wasm-bindgen and placed correctly.');
      }
      const rawResult = checkPlcCode(fileContent, policy || '', fileName || 'uploaded.scl');
    const parsed: any[] = JSON.parse(rawResult);

    // 1. Flatten the nested data structure
    const flattenedResults: AnalysisResult[] = parsed.map((result) => {
      if (result.violation) {
        return { ...result, ...result.violation };
      }
      return result;
    });

    // 2. NEW: Filter out duplicate results
    const uniqueResults: AnalysisResult[] = [];
    const seen = new Set<string>(); // This will store a unique signature for each result seen

    for (const result of flattenedResults) {
      const signature = JSON.stringify(result); // Create a string version of the object
      if (!seen.has(signature)) { // Check if we've seen this exact result before
        seen.add(signature);
        uniqueResults.push(result);
      }
    }

    setResults(uniqueResults); // Use the new, flattened array
      console.log('Analysis results:', flattenedResults);

    } catch (err: any) {
      console.error(err);
      setError(err?.message || 'An error occurred while analyzing the code.');
    } finally {
      setLoading(false);
    }
  };

  /** Clear all inputs and results */
  const clearAll = () => {
    setFileContent('');
    setFileName('');
    setPolicy('');
    setResults([]);
    setError('');
  };

  const hasResults = results && results.length > 0;
  return (
    <div className="min-h-screen p-6 bg-gray-900 text-gray-100 relative">
      <div className="max-w-4xl mx-auto">
        <Header onAbout={() => setShowInfo(true)} />
        <FileInput onFileLoaded={handleFileLoaded} />
        <PolicyInput policy={policy} onPolicyChange={handlePolicyChange} />
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="mt-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded disabled:bg-gray-600 transition-colors"
            onClick={handleAnalyze}
            disabled={loading || !fileContent}
          >
            {loading ? 'Analyzing…' : 'Analyze Code'}
          </button>
          <button
            type="button"
            className="mt-2 px-3 py-2 rounded bg-gray-800 border border-gray-700 hover:bg-gray-700"
            onClick={clearAll}
          >
            Clear
          </button>
          {fileName && (
            <span className="mt-2 text-sm text-gray-400">File: {fileName}</span>
          )}
        </div>
        {error && <p className="mt-3 text-red-400">{error}</p>}
        {hasResults && <ResultsChart results={results} />}
        {hasResults && <ViolationFrequencyChart results={results} />}
        <Results results={results} source={fileContent} />
      </div>
      {loading && (
        <div className="absolute inset-0 bg-black/40 flex items-center justify-center">
          <div className="rounded bg-gray-800 px-4 py-2 border border-gray-700">
            Analyzing… please wait
          </div>
        </div>
      )}
     
      <InfoPage open={showInfo} onClose={() => setShowInfo(false)} />
    </div>
  );
};

export default App;
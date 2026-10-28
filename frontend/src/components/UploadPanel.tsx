import { useId, useRef, useState, type DragEvent, type KeyboardEvent } from 'react';
import { formatBytes } from '../lib/format';
import { MAX_UPLOAD_BYTES, validateSolidityFile } from '../lib/validation';

export interface SampleContract {
  id: string;
  name: string;
  filename: string;
  code: string;
}

export const SAMPLE_CONTRACTS: SampleContract[] = [
  {
    id: 'reentrancy_classic',
    name: 'Reentrancy Classic (EtherBank)',
    filename: 'EtherBank.sol',
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract EtherBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] = 0;
    }
}
`,
  },
  {
    id: 'reentrancy_cross',
    name: 'Cross-Function Reentrancy (SharedLedger)',
    filename: 'SharedLedger.sol',
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract SharedLedger {
    mapping(address => uint256) public userBalances;

    function deposit() public payable {
        userBalances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) public {
        if (userBalances[msg.sender] >= amount) {
            userBalances[to] += amount;
            userBalances[msg.sender] -= amount;
        }
    }

    function withdrawBalance() public {
        uint256 amountToWithdraw = userBalances[msg.sender];
        (bool success, ) = msg.sender.call{value: amountToWithdraw}("");
        require(success);
        userBalances[msg.sender] = 0;
    }
}
`,
  },
  {
    id: 'unchecked_call',
    name: 'Unchecked Low-Level Call',
    filename: 'UncheckedCallLocker.sol',
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract UncheckedCallLocker {
    mapping(address => uint256) public credits;

    function sendReward(address payable recipient, uint256 amount) public {
        recipient.send(amount); // unchecked send
        credits[recipient] = 0;
    }

    function callReward(address payable recipient, uint256 amount) public {
        recipient.call{value: amount}(""); // unchecked call
        credits[recipient] = 0;
    }
}
`,
  },
  {
    id: 'tx_origin',
    name: 'Tx.Origin Phishing Vulnerability',
    filename: 'TxOriginWallet.sol',
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(address payable to, uint256 amount) public {
        require(tx.origin == owner, "Not owner");
        to.transfer(amount);
    }
}
`,
  },
  {
    id: 'benign_token',
    name: 'Secure Token (Benign ERC20)',
    filename: 'SecureToken.sol',
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecureToken {
    string public name = "SecureToken";
    string public symbol = "SEC";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10**18;
    mapping(address => uint256) public balanceOf;

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }
}
`,
  },
];

interface Props {
  onSubmit: (file: File) => void;
  busy?: boolean;
}

export function UploadPanel({ onSubmit, busy = false }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<'upload' | 'paste'>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [pasteCode, setPasteCode] = useState<string>(SAMPLE_CONTRACTS[0]?.code ?? '');
  const [pasteName, setPasteName] = useState<string>(SAMPLE_CONTRACTS[0]?.filename ?? 'Contract.sol');
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const hintId = useId();
  const errId = useId();

  function accept(f: File | undefined | null) {
    if (!f) return;
    const v = validateSolidityFile(f);
    if (!v.ok) {
      setFile(null);
      setError(v.reason);
      return;
    }
    setError(null);
    setFile(f);
  }

  function loadSample(sample: SampleContract) {
    const blob = new Blob([sample.code], { type: 'text/plain' });
    const f = new File([blob], sample.filename, { type: 'text/plain' });
    accept(f);
    setPasteCode(sample.code);
    setPasteName(sample.filename);
  }

  function handlePasteSubmit() {
    if (!pasteCode.trim()) {
      setError('Please provide Solidity source code.');
      return;
    }
    const fname = pasteName.endsWith('.sol') ? pasteName : `${pasteName}.sol`;
    const blob = new Blob([pasteCode], { type: 'text/plain' });
    const f = new File([blob], fname, { type: 'text/plain' });
    const v = validateSolidityFile(f);
    if (!v.ok) {
      setError(v.reason);
      return;
    }
    setError(null);
    onSubmit(f);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    if (busy) return;
    const files = e.dataTransfer?.files;
    if (files && files.length > 1) {
      setFile(null);
      setError('Drop a single .sol file.');
      return;
    }
    accept(files?.[0]);
  }

  function onKey(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      inputRef.current?.click();
    }
  }

  return (
    <section className="card" aria-labelledby="upload-title">
      <div className="card__head">
        <h2 id="upload-title" className="card__title">
          Upload a Solidity contract
        </h2>
        <div className="tab-group" role="tablist" aria-label="Input mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'upload'}
            className={`btn btn--sm ${mode === 'upload' ? 'btn--primary' : 'btn--ghost'}`}
            onClick={() => setMode('upload')}
          >
            File Upload / Dropzone
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'paste'}
            className={`btn btn--sm ${mode === 'paste' ? 'btn--primary' : 'btn--ghost'}`}
            onClick={() => setMode('paste')}
          >
            Paste / Edit Code
          </button>
        </div>
      </div>

      {/* Pre-loaded Sample Selector */}
      <div className="sample-bar" style={{ margin: '14px 0', padding: '10px 14px', background: 'var(--panel-2)', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        <span className="small muted" style={{ fontWeight: 600 }}>Quick load sample:</span>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {SAMPLE_CONTRACTS.map((sc) => (
            <button
              key={sc.id}
              type="button"
              className="btn btn--ghost btn--sm"
              style={{ fontSize: '0.8rem', padding: '4px 8px' }}
              disabled={busy}
              onClick={() => loadSample(sc)}
            >
              ⚡ {sc.name.split(' (')[0]}
            </button>
          ))}
        </div>
      </div>

      {mode === 'upload' ? (
        <>
          <div
            className={`dropzone${dragging ? ' dropzone--active' : ''}${error ? ' dropzone--error' : ''}`}
            role="button"
            tabIndex={busy ? -1 : 0}
            aria-disabled={busy}
            aria-label="Choose or drop a .sol file"
            aria-describedby={`${hintId}${error ? ` ${errId}` : ''}`}
            data-testid="dropzone"
            onClick={() => !busy && inputRef.current?.click()}
            onKeyDown={onKey}
            onDragOver={(e) => {
              e.preventDefault();
              if (!busy) setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
          >
            <svg aria-hidden="true" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" />
            </svg>
            <p className="dropzone__main">
              Drag &amp; drop a <code>.sol</code> file, or <span className="link">browse</span>
            </p>
            <p id={hintId} className="muted small">
              One file, max {formatBytes(MAX_UPLOAD_BYTES)}. Source is analysed in an isolated sandbox.
            </p>
            <input
              ref={inputRef}
              type="file"
              accept=".sol"
              className="visually-hidden"
              data-testid="file-input"
              aria-label="Solidity file"
              tabIndex={-1}
              onChange={(e) => {
                accept(e.target.files?.[0]);
                e.target.value = '';
              }}
            />
          </div>

          {error && (
            <p id={errId} className="field-error" role="alert" style={{ marginTop: '10px' }}>
              {error}
            </p>
          )}

          {file && (
            <div className="file-row" data-testid="selected-file" style={{ marginTop: '14px' }}>
              <span className="file-row__icon" aria-hidden="true">
                ◆
              </span>
              <span className="file-row__name">{file.name}</span>
              <span className="muted">{formatBytes(file.size)}</span>
              <button type="button" className="btn btn--ghost btn--sm" onClick={() => setFile(null)} disabled={busy} aria-label={`Remove ${file.name}`}>
                Remove
              </button>
            </div>
          )}

          <div className="actions" style={{ marginTop: '16px' }}>
            <button type="button" className="btn btn--primary" disabled={!file || busy} onClick={() => file && onSubmit(file)}>
              {busy ? 'Submitting…' : 'Run security analysis'}
            </button>
          </div>
        </>
      ) : (
        <div className="paste-mode" style={{ display: 'grid', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <label htmlFor="sol-filename" className="small muted">Filename:</label>
            <input
              id="sol-filename"
              className="input"
              style={{ width: '220px', padding: '6px 10px' }}
              value={pasteName}
              onChange={(e) => setPasteName(e.target.value)}
              placeholder="Contract.sol"
              disabled={busy}
            />
          </div>
          <textarea
            aria-label="Solidity source code editor"
            className="textarea"
            rows={12}
            spellCheck={false}
            value={pasteCode}
            onChange={(e) => setPasteCode(e.target.value)}
            style={{ fontFamily: 'var(--mono)', fontSize: '0.9rem' }}
            disabled={busy}
          />
          {error && (
            <p className="field-error" role="alert">
              {error}
            </p>
          )}
          <div className="actions">
            <button type="button" className="btn btn--primary" disabled={busy || !pasteCode.trim()} onClick={handlePasteSubmit}>
              {busy ? 'Submitting…' : 'Run security analysis'}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

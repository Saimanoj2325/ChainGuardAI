import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

interface MockFlagCtx {
  dataIsMock: boolean;
  setDataIsMock: (v: boolean) => void;
}

const Ctx = createContext<MockFlagCtx>({ dataIsMock: false, setDataIsMock: () => undefined });

export function MockFlagProvider({ children }: { children: ReactNode }) {
  const [dataIsMock, setDataIsMock] = useState(false);
  return <Ctx.Provider value={{ dataIsMock, setDataIsMock }}>{children}</Ctx.Provider>;
}

export const useMockFlag = () => useContext(Ctx);

/** Pages call this with whether the data they currently display contains mock data. */
export function useReportMock(isMock: boolean): void {
  const { setDataIsMock } = useMockFlag();
  useEffect(() => {
    setDataIsMock(isMock);
    return () => setDataIsMock(false);
  }, [isMock, setDataIsMock]);
}

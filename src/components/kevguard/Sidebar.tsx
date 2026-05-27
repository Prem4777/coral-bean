"use client";

type Props = {
  onNewScan?: () => void;
  active?: "dashboard";
};

export function Sidebar({ onNewScan, active = "dashboard" }: Props) {
  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: <DashboardIcon /> },
  ] as const;

  return (
    <aside className="fixed left-0 top-0 z-50 flex h-screen w-60 flex-col border-r border-white/6 bg-[#07111c]">
      {/* New Scan CTA — top */}
      <div className="px-4 pb-3 pt-5">
        <button
          onClick={onNewScan}
          className="flex w-full items-center gap-2.5 rounded-lg bg-[#45dfa4] px-4 py-2.5 text-[13px] font-semibold text-[#002d1e] transition-all hover:brightness-110 active:scale-[0.98]"
        >
          <PlusIcon />
          New Scan
        </button>
      </div>

      {/* Brand */}
      <div className="flex items-center gap-3 border-b border-white/6 px-5 py-4">
        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-[#45dfa4]/10">
          <svg className="h-4 w-4 text-[#45dfa4]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
        </div>
        <div>
          <span className="block text-[15px] font-semibold tracking-tight text-white">KEVGuard</span>
          <span className="block font-mono text-[10px] uppercase tracking-widest text-white/30">AppSec Intelligence</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4">
        <ul className="space-y-0.5">
          {navItems.map((item) => {
            const isActive = active === item.id;
            return (
              <li key={item.id}>
                <button
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-[14px] transition-colors ${
                    isActive
                      ? "bg-white/8 text-white"
                      : "text-white/50 hover:bg-white/4 hover:text-white/80"
                  }`}
                >
                  <span className={isActive ? "text-[#45dfa4]" : "text-white/30"}>
                    {item.icon}
                  </span>
                  {item.label}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
    </aside>
  );
}

function DashboardIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
    </svg>
  );
}
function ShieldIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
}
function PlusIcon() {
  return (
    <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
    </svg>
  );
}

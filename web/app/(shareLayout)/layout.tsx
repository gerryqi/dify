import type { FC, PropsWithChildren } from 'react'
import WebAppStoreProvider from '@/context/web-app-context'
import FeishuAutoAuth from './components/feishu-auto-auth'
import Splash from './components/splash'

const Layout: FC<PropsWithChildren> = ({ children }) => {
  return (
    <div className="h-full min-w-[300px] pb-[env(safe-area-inset-bottom)]">
      <WebAppStoreProvider>
        <FeishuAutoAuth>
          <Splash>
            {children}
          </Splash>
        </FeishuAutoAuth>
      </WebAppStoreProvider>
    </div>
  )
}

export default Layout

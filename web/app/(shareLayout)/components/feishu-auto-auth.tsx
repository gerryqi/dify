'use client'
import type { FC, PropsWithChildren } from 'react'
import { useCallback, useEffect, useState } from 'react'
import Loading from '@/app/components/base/loading'
import { useWebAppStore } from '@/context/web-app-context'
import { useRouter, useSearchParams } from '@/next/navigation'
import { getWebAppPassport, setWebAppPassport, webAppLoginStatus } from '@/service/webapp-auth'

/**
 * Feishu auto-auth for workplace embedded apps.
 *
 * When a user opens a Dify share app from the Feishu workplace, Feishu appends
 * `?code=xxx` to the URL automatically. This component detects the code,
 * exchanges it for a passport via the backend, and saves the passport — all
 * without showing a login page.
 *
 * If no code is found, it passes through to the existing Splash auth logic.
 */
const FeishuAutoAuth: FC<PropsWithChildren> = ({ children }) => {
  const searchParams = useSearchParams()
  const router = useRouter()
  const shareCode = useWebAppStore(s => s.shareCode)
  const updateWebAppAccessMode = useWebAppStore(s => s.updateWebAppAccessMode)
  const updateUserCanAccessApp = useWebAppStore(s => s.updateUserCanAccessApp)

  // Check URL params for Feishu auth code or existing passport status
  const code = searchParams.get('code')
  const isFeishuCallback = !!code

  const [isFeishuAuthLoading, setIsFeishuAuthLoading] = useState(isFeishuCallback)

  const handleFeishuAutoLogin = useCallback(async () => {
    if (!code || !shareCode) {
      setIsFeishuAuthLoading(false)
      return
    }

    try {
      const res = await fetch('/api/sso/feishu/app-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, app_code: shareCode }),
      })

      if (!res.ok) {
        console.warn('[FeishuAutoAuth] Login failed, falling back to normal auth')
        setIsFeishuAuthLoading(false)
        return
      }

      const data = await res.json()
      if (data.passport) {
        // Save passport — same key as the existing auth flow uses
        setWebAppPassport(shareCode, data.passport)

        // Refresh app access mode since user is now authenticated
        try {
          const modeRes = await fetch(`/api/webapp/access-mode?appCode=${shareCode}`)
          if (modeRes.ok) {
            const { accessMode } = await modeRes.json()
            updateWebAppAccessMode(accessMode)
          }
        }
        catch { /* non-critical, use default */ }

        updateUserCanAccessApp(true)

        // Remove code from URL to prevent re-auth on refresh
        const newParams = new URLSearchParams(searchParams.toString())
        newParams.delete('code')
        const newUrl = `${window.location.pathname}${newParams.toString() ? `?${newParams.toString()}` : ''}`
        window.history.replaceState(null, '', newUrl)
      }
    }
    catch (err) {
      console.error('[FeishuAutoAuth] Request failed:', err)
    }
    finally {
      setIsFeishuAuthLoading(false)
    }
  }, [code, shareCode, searchParams, updateWebAppAccessMode, updateUserCanAccessApp])

  useEffect(() => {
    if (isFeishuCallback)
      handleFeishuAutoLogin()
  }, [isFeishuCallback, handleFeishuAutoLogin])

  if (isFeishuAuthLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loading />
      </div>
    )
  }

  return <>{children}</>
}

export default FeishuAutoAuth

'use client'
import { useSuspenseQuery } from '@tanstack/react-query'
import * as React from 'react'
import { useEffect } from 'react'
import AppUnavailable from '@/app/components/base/app-unavailable'
import Loading from '@/app/components/base/loading'
import { useRouter, useSearchParams } from '@/next/navigation'
import { systemFeaturesQueryOptions } from '@/service/system-features'
import { setWebAppPassport } from '@/service/webapp-auth'

const FeishuCallbackPage = () => {
  const { data: systemFeatures } = useSuspenseQuery(systemFeaturesQueryOptions())
  const router = useRouter()
  const searchParams = useSearchParams()

  const passport = searchParams.get('passport')
  const appCode = searchParams.get('app_code')
  const redirectUrl = searchParams.get('redirect_url')

  useEffect(() => {
    if (!passport || !appCode || !redirectUrl) {
      return
    }

    // Save passport to localStorage
    setWebAppPassport(appCode, passport)

    // Redirect back to original share app page
    router.replace(decodeURIComponent(redirectUrl))
  }, [passport, appCode, redirectUrl, router])

  if (!passport || !appCode || !redirectUrl) {
    return (
      <div className="flex h-full items-center justify-center">
        <AppUnavailable code={400} unknownReason="Missing required callback parameters." />
      </div>
    )
  }

  return (
    <div className="flex h-full items-center justify-center">
      <Loading />
    </div>
  )
}

export default FeishuCallbackPage

'use client'
import { Button } from '@langgenius/dify-ui/button'
import { toast } from '@langgenius/dify-ui/toast'
import { RiFlutterFill } from '@remixicon/react'
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { useRouter, useSearchParams } from '@/next/navigation'

type FeishuSSOAuthProps = {
  appCode: string
}

const FeishuSSOAuth = ({ appCode }: FeishuSSOAuthProps) => {
  const { t } = useTranslation()
  const router = useRouter()
  const searchParams = useSearchParams()

  const redirectUrl = searchParams.get('redirect_url')

  const handleFeishuLogin = useCallback(async () => {
    if (!redirectUrl) {
      toast.error('redirect url is missing')
      return
    }

    try {
      const res = await fetch(`/api/sso/feishu/login?app_code=${encodeURIComponent(appCode)}&redirect_url=${encodeURIComponent(redirectUrl)}`)
      const data = await res.json()
      if (data.url)
        router.push(data.url)
      else
        toast.error(data.message || 'Failed to get Feishu authorization URL')
    }
    catch (e: any) {
      toast.error(e.message || 'Feishu login failed')
    }
  }, [appCode, redirectUrl, router])

  return (
    <Button
      tabIndex={0}
      onClick={() => { handleFeishuLogin() }}
      className="w-full"
    >
      <RiFlutterFill className="mr-2 h-5 w-5 text-text-accent-light-mode-only" />
      <span className="truncate">{t('login.withFeishu', { ns: 'login' }) || 'Login with Feishu'}</span>
    </Button>
  )
}

export default FeishuSSOAuth

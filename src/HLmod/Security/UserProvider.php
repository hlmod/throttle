<?php

namespace App\HLmod\Security;

use Doctrine\DBAL\Connection;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;


class UserProvider implements UserProviderInterface
{
    private $db;
    private $cache;
    private $appConfig;
    private $httpClient;

    public function __construct(Connection $db, CacheInterface $cache, HttpClientInterface $httpClient, $appConfig)
    {
        $this->db = $db;
        $this->cache = $cache;
        $this->appConfig = $appConfig;
        $this->httpClient = $httpClient;
    }

    public function loadUserByUsername($id)
    {
        $baseCacheKey = 'hlmod_user.' . $id;

        $details = $this->cache->get($baseCacheKey . '.details', function () use ($id, $baseCacheKey)
        {
            $query = '
SELECT
    `name`, `avatar`, UNIX_TIMESTAMP(`lastactive`) AS `lastactive`
FROM
    `user`
WHERE
    `id` = ? LIMIT 1';

            $details = $this->db->executeQuery($query, [$id])->fetch();
            if (!$details)
            {
                $this->db->executeQuery('INSERT IGNORE INTO `user` (`id`) VALUES(?)', [$id]);
            }

            $info = $this->safeFetchInformationById($id, false);
            if (!$details || (time() - $details['lastactive']) > 43200)
            {
                $username = $info['username'];
                $avatar = $info['avatar_urls']['o'] ?? '';

                // Update user information every 12 hours
                $query = '
UPDATE
    `user`
SET
    `lastactive` = NOW(),
    `name` = ?,
    `avatar` = ?
WHERE `id` = ?';
                $this->db->executeQuery($query, [$username, $avatar, $id]);

                $details = [
                    'name' => $username,
                    'avatar' => $avatar,
                    'lastactive' => time()
                ];
            }

            $details['is_admin'] = ($info['is_staff'] || $info['is_moderator'] || $info['is_admin']);
            return $details;
        }, 43200);

        $details['pending'] = $this->cache->get('hlmod_pending_crashes.' . $id, function () use ($id)
        {
            $query = '
SELECT
    COUNT(*) AS `count`
FROM
    `share`
WHERE
    `user` = ?
    AND `accepted` IS NULL
            ';

            return $this->db->executeQuery($query, [$id])->fetchColumn(0);
        }, 30);

        $user = new Member($id);
        $user->setName($details['name'] ?? null)
            ->setAvatar($details['avatar'] ?? null)
            ->setIsAdmin($details['is_admin'] ?? false)
            ->setPending($details['pending'] ?? 0);

        return $user;
    }

    /**
     * Periodically, we update user in loadUserByUsername(), so this is just a stub.
     *
     * @param UserInterface $user
     * @return UserInterface
     */
    public function refreshUser(UserInterface $user)
    {
        return $user;
    }

    public function supportsClass($class)
    {
        return $class === Member::class;
    }

    protected function fetchInformationById($id, $bypassCache = false)
    {
        $cacheKey = 'hlmod_api_request_user.' . $id;
        if ($bypassCache)
        {
            $this->cache->delete($cacheKey);
            return $this->fetchInformationById($id, false);
        }

        return $this->cache->get($cacheKey, function () use ($id)
        {
            $response = $this->httpClient->request('GET', 'https://hlmod.ru/api/users/' . $id . '/', [
                'headers' => [
                    'XF-Api-Key' => $this->appConfig['xfApiKey']
                ]
            ]);

            if ($response->getStatusCode() === 404)
            {
                throw new UsernameNotFoundException();
            }

            $body = json_decode($response->getContent(), true);
            return $body['user'];
        }, 43200);
    }

    protected function safeFetchInformationById($id, $bypassCache = false)
    {
        try
        {
            return $this->fetchInformationById($id);
        }
        catch (\Exception $e)
        {
            return [];
        }
    }
}

<?php namespace Stevenmaguire\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\GenericResourceOwner;

/**
 * @property array $response
 * @property string $resourceOwnerId
 */
class BoxResourceOwner extends GenericResourceOwner
{
    /**
     * Get resource owner id
     *
     * @return string
     */
    public function getId()
    {
        return $this->resourceOwnerId;
    }

    /**
     * Get resource owner email
     *
     * @return string
     */
    public function getEmail()
    {
        return $this->response['login'] ?: null;
    }

    /**
     * Get resource owner name
     *
     * @return string
     */
    public function getName()
    {
        return $this->response['name'] ?: null;
    }

    /**
     * Get resource owner avatar url
     *
     * @return string
     */
    public function getAvatarUrl()
    {
        return $this->response['avatar_url'] ?: null;
    }
}

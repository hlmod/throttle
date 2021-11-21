<?php

namespace App\HLmod\Security;

use Symfony\Component\Security\Core\User\UserInterface;

class Member implements UserInterface
{
    protected const DEFAULT_ID = -1;
    protected const DEFAULT_NAME = 'unnamed';
    protected const DEFAULT_AVATAR = '/util/default_avatar';

    private $id = self::DEFAULT_ID;
    private $name = self::DEFAULT_NAME;
    private $avatar = self::DEFAULT_AVATAR;
    private $pending = 0;
    private $isAdmin = false;

    public function __construct(?int $id)
    {
        $this->setId($id);
    }

    #region id
    /**
     * Retrieves the user unique identifier.
     *
     * @return positive-int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * Sets the user unique identifier.
     *
     * @param positive-int|null $id
     * @return $this
     */
    public function setId(?int $id): self
    {
        $this->id = $id ?? self::DEFAULT_ID;
        return $this;
    }
    #endregion

    #region name
    /**
     * Retrieves the user name.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Sets the user name.
     *
     * @param string|null $name
     * @return $this
     */
    public function setName(?string $name): self
    {
        $this->name = $name ?? self::DEFAULT_NAME;
        return $this;
    }
    #endregion

    #region avatar
    /**
     * Retrieves the user avatar.
     *
     * @return string
     */
    public function getAvatar(): string
    {
        return $this->avatar;
    }

    /**
     * Sets the user avatar.
     *
     * @param string|null $avatar
     * @return $this
     */
    public function setAvatar(?string $avatar): self
    {
        $this->avatar = $avatar ?? self::DEFAULT_AVATAR;
        return $this;
    }
    #endregion

    #region admin
    /**
     * Retrieves the user admin attribute.
     *
     * @return bool
     */
    public function isAdmin(): bool
    {
        return $this->isAdmin;
    }

    /**
     * Sets the user admin attribute.
     *
     * @param bool
     * @return $this
     */
    public function setIsAdmin(bool $isAdmin = false): self
    {
        $this->isAdmin = $isAdmin;
        return $this;
    }

    #endregion

    #region pending

    /**
     * @return int
     */
    public function getPending(): int
    {
        return $this->pending;
    }

    /**
     * @param int $pending
     * @return $this
     */
    public function setPending(int $pending): self
    {
        $this->pending = $pending;
        return $this;
    }

    #endregion

    /**
     * Retrieves the user role names.
     *
     * @return string[]
     */
    public function getRoles()
    {
        $roles = ['ROLE_USER'];
        if ($this->isAdmin())
        {
            $roles[] = 'ROLE_ADMIN';
        }

        return $roles;
    }

    /**
     * Retrieves the user password used of authenticate process.
     * We use OAuth2, so we don't know what password is used.
     *
     * @return null
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * Returns the salt that was originally used to encode the password.
     * We use OAuth2, so we don't know what salt is used.
     *
     * @return null
     */
    public function getSalt()
    {
        // Not need. We're using third-party authentication provider.
        return null;
    }

    /**
     * Returns the username used to authenticate the user.
     * @return string
     */
    public function getUsername()
    {
        return $this->getName();
    }

    /**
     * Removes sensitive data from the user.
     */
    public function eraseCredentials()
    {
    }
}

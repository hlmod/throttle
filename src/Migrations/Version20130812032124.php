<?php

namespace ThrottleMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

class Version20130812032124 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        $this->addSql('UPDATE frame SET rendered = IF(file != \'\', CONCAT(module, \'!\', function, \' [\', SUBSTRING_INDEX(REPLACE(file, \'\\\\\', \'/\'), \'/\', -1), \':\', line, \' + \', offset, \']\'), IF(function != \'\', CONCAT(module, \'!\', function, \' + \', offset), IF(module != \'\', CONCAT(module, \' + \', offset), offset))) WHERE rendered IS NULL');
    }

    public function down(Schema $schema): void
    {
    }
}

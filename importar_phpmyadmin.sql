-- ================================================================
-- SCRIPT PARA XAMPP / phpMyAdmin (MariaDB 10.4+ compatible)
-- Pegar completo en la pestaña SQL de phpMyAdmin
-- Base de Datos: auditoria_sustentable
-- ================================================================

CREATE DATABASE IF NOT EXISTS `auditoria_sustentable`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `auditoria_sustentable`;

-- ================================================================
-- 1. PLATAFORMAS / PROYECTOS AUDITADOS
-- ================================================================
CREATE TABLE `plataformas` (
    `id`              INT(11)       NOT NULL AUTO_INCREMENT,
    `nombre`          VARCHAR(100)  NOT NULL,
    `descripcion`     TEXT          NULL DEFAULT NULL,
    `url_base`        VARCHAR(255)  NULL DEFAULT NULL,
    `tecnologia_front` VARCHAR(100) NULL DEFAULT NULL,
    `tecnologia_back`  VARCHAR(100) NULL DEFAULT NULL,
    `proveedor_cloud`  VARCHAR(100) NULL DEFAULT NULL,
    `created_at`      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 2. PLANES DE AUDITORÍA
-- ================================================================
CREATE TABLE `planes_auditoria` (
    `id`              INT(11)       NOT NULL AUTO_INCREMENT,
    `plataforma_id`   INT(11)       NOT NULL,
    `nombre`          VARCHAR(150)  NOT NULL,
    `objetivo`        TEXT          NULL DEFAULT NULL,
    `alcance`         TEXT          NULL DEFAULT NULL,
    `fecha_inicio`    DATE          NULL DEFAULT NULL,
    `fecha_fin`       DATE          NULL DEFAULT NULL,
    `estado`          ENUM('planificado','en_curso','completado','cancelado') NOT NULL DEFAULT 'planificado',
    `created_at`      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `fk_plan_plataforma` (`plataforma_id`),
    CONSTRAINT `fk_plan_plataforma` FOREIGN KEY (`plataforma_id`) REFERENCES `plataformas` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 3. ÁREAS DE AUDITORÍA (cada ítem del plan: a, b, c, ..., m)
-- ================================================================
CREATE TABLE `areas_auditoria` (
    `id`              INT(11)       NOT NULL AUTO_INCREMENT,
    `plan_id`         INT(11)       NOT NULL,
    `codigo`          VARCHAR(10)   NOT NULL COMMENT 'a, b, c, ..., m',
    `nombre`          VARCHAR(150)  NOT NULL,
    `descripcion`     TEXT          NULL DEFAULT NULL,
    `prioridad`       ENUM('baja','media','alta','critica') NOT NULL DEFAULT 'media',
    `estado`          ENUM('pendiente','en_progreso','completado','bloqueado') NOT NULL DEFAULT 'pendiente',
    PRIMARY KEY (`id`),
    KEY `fk_area_plan` (`plan_id`),
    CONSTRAINT `fk_area_plan` FOREIGN KEY (`plan_id`) REFERENCES `planes_auditoria` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 4. HALLAZGOS DE AUDITORÍA
-- ================================================================
CREATE TABLE `hallazgos` (
    `id`                INT(11)       NOT NULL AUTO_INCREMENT,
    `area_id`           INT(11)       NOT NULL,
    `titulo`            VARCHAR(200)  NOT NULL,
    `descripcion`       TEXT          NULL DEFAULT NULL,
    `impacto`           ENUM('bajo','medio','alto','critico') NOT NULL DEFAULT 'medio',
    `probabilidad`      ENUM('baja','media','alta') NOT NULL DEFAULT 'media',
    `estado`            ENUM('abierto','en_revision','remediado','aceptado','falso_positivo') NOT NULL DEFAULT 'abierto',
    `evidencia`         TEXT          NULL DEFAULT NULL COMMENT 'ruta archivo o JSON',
    `recomendacion`     TEXT          NULL DEFAULT NULL,
    `fecha_hallazgo`    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `fecha_remediacion` DATETIME      NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_hallazgo_area` (`area_id`),
    KEY `idx_hallazgos_estado` (`estado`),
    CONSTRAINT `fk_hallazgo_area` FOREIGN KEY (`area_id`) REFERENCES `areas_auditoria` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 5. VULNERABILIDADES (CVE / dependencias)
-- ================================================================
CREATE TABLE `vulnerabilidades` (
    `id`                  INT(11)       NOT NULL AUTO_INCREMENT,
    `hallazgo_id`         INT(11)       NULL DEFAULT NULL,
    `cve_id`              VARCHAR(20)   NULL DEFAULT NULL COMMENT 'CVE-YYYY-XXXXX',
    `paquete`             VARCHAR(150)  NULL DEFAULT NULL COMMENT 'nombre librería',
    `version_actual`      VARCHAR(50)   NULL DEFAULT NULL,
    `version_minima_segura` VARCHAR(50) NULL DEFAULT NULL,
    `tipo`                ENUM('libreria','configuracion','arquitectura','api','token','ia','otro') NOT NULL DEFAULT 'libreria',
    `cvss_score`          DECIMAL(3,1)  NULL DEFAULT NULL COMMENT '0.0 - 10.0',
    `cvss_vector`         VARCHAR(100)  NULL DEFAULT NULL,
    `severidad`           ENUM('none','low','medium','high','critical') GENERATED ALWAYS AS (
        CASE
            WHEN `cvss_score` >= 9.0 THEN 'critical'
            WHEN `cvss_score` >= 7.0 THEN 'high'
            WHEN `cvss_score` >= 4.0 THEN 'medium'
            WHEN `cvss_score` >  0.0 THEN 'low'
            ELSE 'none'
        END
    ) STORED,
    `descripcion`         TEXT          NULL DEFAULT NULL,
    `fuente`              VARCHAR(100)  NULL DEFAULT NULL COMMENT 'npm audit, pip-audit, snyk, etc.',
    PRIMARY KEY (`id`),
    KEY `fk_vuln_hallazgo` (`hallazgo_id`),
    KEY `idx_vuln_cve` (`cve_id`),
    KEY `idx_vuln_severidad` (`severidad`),
    CONSTRAINT `fk_vuln_hallazgo` FOREIGN KEY (`hallazgo_id`) REFERENCES `hallazgos` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 6. MATRIZ DE RIESGOS (CSVV)
-- ================================================================
CREATE TABLE `matriz_riesgos` (
    `id`                  INT(11)       NOT NULL AUTO_INCREMENT,
    `plan_id`             INT(11)       NOT NULL,
    `codigo_riesgo`       VARCHAR(10)   NOT NULL COMMENT 'R01, R02, ...',
    `descripcion`         TEXT          NOT NULL,
    `impacto`             ENUM('bajo','medio','alto','critico') NOT NULL,
    `probabilidad`        ENUM('baja','media','alta') NOT NULL,
    `nivel_riesgo`        ENUM('bajo','medio','alto','critico') GENERATED ALWAYS AS (
        CASE
            WHEN `impacto` IN ('critico','alto') AND `probabilidad` = 'alta' THEN 'critico'
            WHEN `impacto` = 'critico' AND `probabilidad` IN ('media','alta') THEN 'alto'
            WHEN `impacto` = 'alto' AND `probabilidad` = 'media' THEN 'alto'
            WHEN `impacto` = 'medio' AND `probabilidad` = 'alta' THEN 'alto'
            WHEN `impacto` = 'bajo' AND `probabilidad` = 'alta' THEN 'medio'
            WHEN `impacto` = 'critico' AND `probabilidad` = 'baja' THEN 'medio'
            WHEN `impacto` = 'alto' AND `probabilidad` = 'baja' THEN 'medio'
            WHEN `impacto` = 'medio' AND `probabilidad` = 'media' THEN 'medio'
            WHEN `impacto` = 'bajo' AND `probabilidad` = 'media' THEN 'bajo'
            WHEN `impacto` = 'medio' AND `probabilidad` = 'baja' THEN 'bajo'
            ELSE 'bajo'
        END
    ) STORED,
    `prioridad`           ENUM('planificar','semana_4+','semana_3-4','semana_2-3','semana_1-2','inmediata') NOT NULL DEFAULT 'planificar',
    `categoria`           VARCHAR(50)   NULL DEFAULT NULL COMMENT 'token, ia, acceso, dependencias, etc.',
    `estado`              ENUM('identificado','en_revision','mitigado','aceptado') NOT NULL DEFAULT 'identificado',
    `plan_accion`         TEXT          NULL DEFAULT NULL,
    `fecha_identificacion` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `fk_riesgo_plan` (`plan_id`),
    KEY `idx_riesgos_nivel` (`nivel_riesgo`),
    KEY `idx_riesgos_categoria` (`categoria`),
    CONSTRAINT `fk_riesgo_plan` FOREIGN KEY (`plan_id`) REFERENCES `planes_auditoria` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 7. PROVEEDORES DE AUTENTICACIÓN
-- ================================================================
CREATE TABLE `auth_proveedores` (
    `id`              INT(11)       NOT NULL AUTO_INCREMENT,
    `plataforma_id`   INT(11)       NOT NULL,
    `nombre`          VARCHAR(50)   NOT NULL COMMENT 'Google, Local, LinkedIn',
    `tipo`            ENUM('oauth2','jwt','saml','password') NOT NULL,
    `configuracion`   LONGTEXT      NULL DEFAULT NULL COMMENT 'JSON con client_id, endpoints, etc.',
    `activo`          TINYINT(1)    NOT NULL DEFAULT 1,
    PRIMARY KEY (`id`),
    KEY `fk_auth_plataforma` (`plataforma_id`),
    CONSTRAINT `fk_auth_plataforma` FOREIGN KEY (`plataforma_id`) REFERENCES `plataformas` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 8. AUDITORÍA DE TOKENS JWT
-- ================================================================
CREATE TABLE `tokens_auditoria` (
    `id`                   INT(11)       NOT NULL AUTO_INCREMENT,
    `plataforma_id`        INT(11)       NOT NULL,
    `token_ttl_segundos`   INT(11)       NULL DEFAULT NULL COMMENT 'tiempo de vida del token',
    `refresh_ttl_segundos` INT(11)       NULL DEFAULT NULL,
    `algoritmo`            VARCHAR(10)   NULL DEFAULT NULL COMMENT 'HS256, RS256',
    `verificacion_refresh` TINYINT(1)    NOT NULL DEFAULT 0,
    `rotacion_activa`      TINYINT(1)    NOT NULL DEFAULT 0,
    `riesgo`               TEXT          NULL DEFAULT NULL,
    `recomendacion`        TEXT          NULL DEFAULT NULL,
    `fecha_analisis`       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `fk_token_plataforma` (`plataforma_id`),
    CONSTRAINT `fk_token_plataforma` FOREIGN KEY (`plataforma_id`) REFERENCES `plataformas` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 9. ENDPOINTS / APIs (inventario)
-- ================================================================
CREATE TABLE `api_endpoints` (
    `id`              INT(11)       NOT NULL AUTO_INCREMENT,
    `plataforma_id`   INT(11)       NOT NULL,
    `metodo`          ENUM('GET','POST','PUT','PATCH','DELETE','OPTIONS') NOT NULL,
    `ruta`            VARCHAR(255)  NOT NULL,
    `requiere_auth`   TINYINT(1)    NOT NULL DEFAULT 1,
    `rate_limit`      VARCHAR(50)   NULL DEFAULT NULL COMMENT 'ej: 100/min',
    `parametros`      LONGTEXT      NULL DEFAULT NULL COMMENT 'JSON',
    `descripcion`     TEXT          NULL DEFAULT NULL,
    `riesgo`          ENUM('bajo','medio','alto','critico') NOT NULL DEFAULT 'medio',
    PRIMARY KEY (`id`),
    KEY `fk_api_plataforma` (`plataforma_id`),
    CONSTRAINT `fk_api_plataforma` FOREIGN KEY (`plataforma_id`) REFERENCES `plataformas` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 10. PRUEBAS DE PROMPT INJECTION
-- ================================================================
CREATE TABLE `prompt_injection_pruebas` (
    `id`                INT(11)       NOT NULL AUTO_INCREMENT,
    `area_id`           INT(11)       NOT NULL,
    `payload`           TEXT          NOT NULL COMMENT 'texto inyectado',
    `tecnica`           VARCHAR(50)   NULL DEFAULT NULL COMMENT 'jailbreak, leak_system, ignore_instructions',
    `respuesta_obtenida` TEXT         NULL DEFAULT NULL,
    `leak_detectado`    TINYINT(1)    NOT NULL DEFAULT 0,
    `severidad`         ENUM('bajo','medio','alto','critico') NOT NULL DEFAULT 'medio',
    `fecha_prueba`      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `fk_prompt_area` (`area_id`),
    CONSTRAINT `fk_prompt_area` FOREIGN KEY (`area_id`) REFERENCES `areas_auditoria` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 11. PROTECCIÓN DE SKILLS (IA)
-- ================================================================
CREATE TABLE `skills_proteccion` (
    `id`              INT(11)       NOT NULL AUTO_INCREMENT,
    `plataforma_id`   INT(11)       NOT NULL,
    `nombre_skill`    VARCHAR(150)  NULL DEFAULT NULL,
    `descripcion`     TEXT          NULL DEFAULT NULL,
    `ofuscada`        TINYINT(1)    NOT NULL DEFAULT 0,
    `leak_posible`    TINYINT(1)    NOT NULL DEFAULT 0,
    `riesgo`          TEXT          NULL DEFAULT NULL,
    `mitigacion`      TEXT          NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_skill_plataforma` (`plataforma_id`),
    CONSTRAINT `fk_skill_plataforma` FOREIGN KEY (`plataforma_id`) REFERENCES `plataformas` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 12. CONFIGURACIÓN DE RESPALDOS
-- ================================================================
CREATE TABLE `respaldos_config` (
    `id`                      INT(11)       NOT NULL AUTO_INCREMENT,
    `plataforma_id`           INT(11)       NOT NULL,
    `tipo_dato`               VARCHAR(50)   NULL DEFAULT NULL COMMENT 'base_datos, blobs, config, skills',
    `frecuencia`              VARCHAR(50)   NULL DEFAULT NULL COMMENT 'diario, semanal',
    `retention_dias`          INT(11)       NULL DEFAULT NULL,
    `ultimo_respaldo`         DATETIME      NULL DEFAULT NULL,
    `ultima_prueba_restauracion` DATETIME   NULL DEFAULT NULL,
    `almacenamiento`          VARCHAR(100)  NULL DEFAULT NULL COMMENT 'Azure Blob, AWS S3',
    `cumple_politica`         TINYINT(1)    NOT NULL DEFAULT 0,
    `observaciones`           TEXT          NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_respaldo_plataforma` (`plataforma_id`),
    CONSTRAINT `fk_respaldo_plataforma` FOREIGN KEY (`plataforma_id`) REFERENCES `plataformas` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 13. TAREAS DE REMEDIACIÓN
-- ================================================================
CREATE TABLE `tareas_remediacion` (
    `id`                INT(11)       NOT NULL AUTO_INCREMENT,
    `hallazgo_id`       INT(11)       NULL DEFAULT NULL,
    `riesgo_id`         INT(11)       NULL DEFAULT NULL,
    `descripcion`       TEXT          NOT NULL,
    `responsable`       VARCHAR(100)  NULL DEFAULT NULL,
    `prioridad`         ENUM('baja','media','alta','critica') NOT NULL DEFAULT 'media',
    `estado`            ENUM('pendiente','en_progreso','completada','cancelada') NOT NULL DEFAULT 'pendiente',
    `fecha_limite`      DATE          NULL DEFAULT NULL,
    `fecha_completada`  DATETIME      NULL DEFAULT NULL,
    `notas`             TEXT          NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_tarea_hallazgo` (`hallazgo_id`),
    KEY `fk_tarea_riesgo` (`riesgo_id`),
    CONSTRAINT `fk_tarea_hallazgo` FOREIGN KEY (`hallazgo_id`) REFERENCES `hallazgos` (`id`) ON DELETE SET NULL,
    CONSTRAINT `fk_tarea_riesgo` FOREIGN KEY (`riesgo_id`) REFERENCES `matriz_riesgos` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 14. USUARIOS DEL SISTEMA DE AUDITORÍA
-- ================================================================
CREATE TABLE `usuarios` (
    `id`              INT(11)       NOT NULL AUTO_INCREMENT,
    `nombre`          VARCHAR(100)  NOT NULL,
    `email`           VARCHAR(150)  NOT NULL,
    `rol`             ENUM('auditor','admin','lector') NOT NULL DEFAULT 'lector',
    `activo`          TINYINT(1)    NOT NULL DEFAULT 1,
    `created_at`      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_usuario_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- 15. LOG DE ACTIVIDADES
-- ================================================================
CREATE TABLE `log_actividades` (
    `id`              BIGINT(20)    NOT NULL AUTO_INCREMENT,
    `usuario_id`      INT(11)       NULL DEFAULT NULL,
    `accion`          VARCHAR(100)  NOT NULL COMMENT 'INSERT, UPDATE, DELETE hallazgo, etc.',
    `tabla_afectada`  VARCHAR(50)   NULL DEFAULT NULL,
    `registro_id`     INT(11)       NULL DEFAULT NULL,
    `detalle`         LONGTEXT      NULL DEFAULT NULL COMMENT 'JSON',
    `ip_address`      VARCHAR(45)   NULL DEFAULT NULL,
    `created_at`      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `fk_log_usuario` (`usuario_id`),
    KEY `idx_log_fecha` (`created_at`),
    CONSTRAINT `fk_log_usuario` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ================================================================
-- DATOS INICIALES
-- ================================================================

INSERT INTO `plataformas` (`nombre`, `descripcion`, `url_base`, `tecnologia_front`, `tecnologia_back`, `proveedor_cloud`)
VALUES (
    '+Sustentable',
    'Plataforma de autodiagnóstico y generación de informes con IA para sostenibilidad empresarial.',
    'https://www.sustentable.cl',
    'Vite + JavaScript (React-like)',
    'FastAPI (Python)',
    'Microsoft Azure'
);

INSERT INTO `usuarios` (`nombre`, `email`, `rol`) VALUES
    ('Admin Auditoría', 'admin@auditoria.cl', 'admin'),
    ('Auditor L1', 'auditor1@auditoria.cl', 'auditor'),
    ('Auditor L2', 'auditor2@auditoria.cl', 'auditor');
